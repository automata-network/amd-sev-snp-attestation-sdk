use base64::prelude::*;
use serde::de::{self, Deserializer};
use serde::Deserialize;
use sev_snp_lib::attestation::AttestationReport;
use sev_snp_lib::types::ProcType;
use std::cmp::Ordering;
use std::collections::BTreeMap as Map;
use std::str::from_utf8;
use tpm_lib::constants::{TPM_ALG_SHA1, TPM_ALG_SHA256};
use tpm_lib::tpm::{FromBytes, TPMSAttest};
use x509_verifier_rust_crypto::sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ApiOpt {
    Sev,
    SevIma,
    SevTpm,
}

impl ApiOpt {
    pub fn from_output(output: &Output) -> Self {
        if output.ima_measurement.is_some() {
            if output.tpm.is_some() {
                ApiOpt::SevTpm
            } else {
                ApiOpt::SevIma
            }
        } else {
            ApiOpt::Sev
        }
    }

    pub fn from_bytes(raw: u8) -> Self {
        match raw {
            0 => ApiOpt::Sev,
            1 => ApiOpt::SevIma,
            2 => ApiOpt::SevTpm,
            _ => panic!("Unknown ApiOpt"),
        }
    }

    pub fn to_bytes(&self) -> u8 {
        match self {
            ApiOpt::Sev => 0,
            ApiOpt::SevIma => 1,
            ApiOpt::SevTpm => 2,
        }
    }
}

#[derive(Debug)]
pub struct Tpm {
    pub quote: Vec<u8>,
    pub signature: Vec<u8>,
    pub pcr10_hash_algo: u16,
    pub pcr10_value: Vec<u8>,
    pub ak_der_chain: Vec<Vec<u8>>,
    pub ek_der_chain: Option<Vec<Vec<u8>>>,
}

impl Tpm {
    pub fn from_bytes(raw_tpm_bytes: &[u8]) -> Self {
        let mut offset = 0usize;

        let quote_len = u32::from_le_bytes([
            raw_tpm_bytes[0],
            raw_tpm_bytes[1],
            raw_tpm_bytes[2],
            raw_tpm_bytes[3],
        ]) as usize;
        offset += 4;

        let mut quote = Vec::with_capacity(quote_len);
        quote.extend_from_slice(&raw_tpm_bytes[offset..offset + quote_len]);
        offset += quote_len;

        let sig_len =
            u16::from_le_bytes([raw_tpm_bytes[offset], raw_tpm_bytes[offset + 1]]) as usize;
        offset += 2;

        let mut signature = Vec::with_capacity(sig_len);
        signature.extend_from_slice(&raw_tpm_bytes[offset..offset + sig_len]);
        offset += sig_len;

        let pcr10_hash_algo =
            u16::from_le_bytes([raw_tpm_bytes[offset], raw_tpm_bytes[offset + 1]]);
        offset += 2;

        let mut pcr10_value = vec![];
        match pcr10_hash_algo {
            TPM_ALG_SHA1 => {
                pcr10_value.extend_from_slice(&raw_tpm_bytes[offset..offset + 20]);
                offset += 20;
            }
            TPM_ALG_SHA256 => {
                pcr10_value.extend_from_slice(&raw_tpm_bytes[offset..offset + 32]);
                offset += 32;
            }
            _ => panic!("Unknown PCR10 hash algorithm"),
        }

        let (ak_der_chain, ak_offset) = get_raw_der_chain_and_offset(&raw_tpm_bytes[offset..]);
        offset += ak_offset;

        let mut ek_der_chain: Option<Vec<Vec<u8>>> = None;
        if offset < raw_tpm_bytes.len() {
            let (ek_chain, ek_offset) = get_raw_der_chain_and_offset(&raw_tpm_bytes[offset..]);
            ek_der_chain = Some(ek_chain);
            offset += ek_offset;
        }

        assert!(offset == raw_tpm_bytes.len());

        Tpm {
            quote,
            signature,
            pcr10_hash_algo,
            pcr10_value,
            ak_der_chain,
            ek_der_chain,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut ret = Vec::new();

        ret.extend_from_slice(&u32::to_le_bytes(self.quote.len() as u32));
        ret.extend_from_slice(&self.quote);
        ret.extend_from_slice(&u16::to_le_bytes(self.signature.len() as u16));
        ret.extend_from_slice(&self.signature);
        ret.extend_from_slice(&u16::to_le_bytes(self.pcr10_hash_algo));
        ret.extend_from_slice(&self.pcr10_value);
        ret.extend_from_slice(&flatten_der_chain(self.ak_der_chain.clone()));

        if let Some(ek) = self.ek_der_chain.clone() {
            ret.extend_from_slice(&flatten_der_chain(ek));
        }

        ret
    }
}

pub fn get_raw_der_chain_and_offset(input: &[u8]) -> (Vec<Vec<u8>>, usize) {
    let mut offset = 0usize;
    let data_count = u32::from_le_bytes([
        input[offset],
        input[offset + 1],
        input[offset + 2],
        input[offset + 3],
    ]) as usize;

    let mut data: Vec<Vec<u8>> = Vec::with_capacity(data_count);

    if data_count > 0 {
        offset += 4;
        let mut data_offset = offset + 4 * data_count;
        for _ in 0..data_count {
            let data_len = u32::from_le_bytes([
                input[offset],
                input[offset + 1],
                input[offset + 2],
                input[offset + 3],
            ]) as usize;
            offset += 4;

            let mut element: Vec<u8> = Vec::with_capacity(data_len);
            element.extend_from_slice(&input[data_offset..data_offset + data_len]);
            data_offset += data_len;

            data.push(element);
        }
        offset = data_offset;
    }

    (data, offset)
}

#[derive(Debug)]
pub struct Parsed<'a> {
    pub api_opt: ApiOpt,
    pub nonce: Vec<u8>,
    pub raw_sev_attestation: Vec<u8>,
    pub vek_der_chain: Vec<Vec<u8>>,
    pub ima_measurement: Option<&'a str>,
    pub tpm_pcr10_attestation: Option<Tpm>,
}

impl Parsed<'_> {
    pub fn serialize_journal(&self, processor_model: ProcType) -> Vec<u8> {
        let mut ret: Vec<u8> = Vec::new();

        ret.extend_from_slice(&[self.api_opt.to_bytes()]);
        ret.extend_from_slice(&[processor_model.to_u8()]);
        ret.extend_from_slice(&u32::to_be_bytes(self.raw_sev_attestation.len() as u32));
        ret.extend_from_slice(&self.raw_sev_attestation);

        ret.extend_from_slice(&sha2_der(&self.vek_der_chain[self.vek_der_chain.len() - 1]));

        if let Some(tpm) = self.tpm_pcr10_attestation.as_ref() {
            ret.extend_from_slice(&u32::to_be_bytes(tpm.quote.len() as u32));
            ret.extend_from_slice(&tpm.quote);
            ret.extend_from_slice(&u16::to_be_bytes(tpm.pcr10_hash_algo));
            ret.extend_from_slice(&tpm.pcr10_value);

            ret.extend_from_slice(&sha2_der(&tpm.ak_der_chain[tpm.ak_der_chain.len() - 1]));

            let ek_der_chain = tpm.ek_der_chain.clone().unwrap_or_else(|| vec![]);
            if ek_der_chain.len() > 0 {
                ret.extend_from_slice(&sha2_der(&ek_der_chain[ek_der_chain.len() - 1]));
            }
        }

        ret
    }
}

pub fn serialize_guest_input(
    api_opt: ApiOpt,
    nonce: &[u8],
    raw_sev_attestation: &[u8],
    vek_der_chain: Vec<Vec<u8>>,
    ima_measurement: Option<&str>,
    tpm_pcr10_obj: Option<Tpm>,
) -> Vec<u8> {
    let mut ret = Vec::new();

    ret.extend_from_slice(&[api_opt.to_bytes()]);
    ret.extend_from_slice(&u32::to_le_bytes(nonce.len() as u32));
    ret.extend_from_slice(nonce);
    ret.extend_from_slice(&u32::to_le_bytes(raw_sev_attestation.len() as u32));
    ret.extend_from_slice(raw_sev_attestation);
    ret.extend_from_slice(&flatten_der_chain(vek_der_chain));

    if let Some(ima_str) = ima_measurement {
        let ima_bytes = ima_str.as_bytes();
        let ima_len = ima_bytes.len() as u32;
        ret.extend_from_slice(&u32::to_le_bytes(ima_len));
        ret.extend_from_slice(ima_bytes);
    }

    if let Some(tpm_quote_att) = tpm_pcr10_obj {
        ret.extend_from_slice(&tpm_quote_att.to_bytes());
    }

    ret
}

fn flatten_der_chain(der_chain: Vec<Vec<u8>>) -> Vec<u8> {
    let mut ret = Vec::new();

    let der_count = der_chain.len() as u32;
    ret.extend_from_slice(&der_count.to_le_bytes());

    if der_count > 0 {
        // Get the length of each element
        for d in der_chain.iter() {
            let d_len = d.len() as u32;
            ret.extend_from_slice(&d_len.to_le_bytes());
        }

        let flattened: Vec<u8> = der_chain.into_iter().flatten().collect();
        ret.extend_from_slice(&flattened);
    }

    ret
}

pub fn deserialize_guest_input(input: &[u8]) -> Parsed {
    let mut offset = 0usize;
    let api_opt = ApiOpt::from_bytes(input[0]);
    offset += 1;

    let nonce_len = u32::from_le_bytes([
        input[offset],
        input[offset + 1],
        input[offset + 2],
        input[offset + 3],
    ]) as usize;
    offset += 4;

    let mut nonce = Vec::with_capacity(nonce_len);
    nonce.extend_from_slice(&input[offset..offset + nonce_len]);
    offset += nonce_len;

    let sev_len = u32::from_le_bytes([
        input[offset],
        input[offset + 1],
        input[offset + 2],
        input[offset + 3],
    ]) as usize;
    offset += 4;
    let mut raw_sev_attestation = Vec::with_capacity(sev_len);
    raw_sev_attestation.extend_from_slice(&input[offset..offset + sev_len]);
    offset += sev_len;

    let (vek_der_chain, vek_offset) = get_raw_der_chain_and_offset(&input[offset..]);
    offset += vek_offset;

    let ima_measurement: Option<&str>;
    if api_opt != ApiOpt::Sev {
        let ima_len = u32::from_le_bytes([
            input[offset],
            input[offset + 1],
            input[offset + 2],
            input[offset + 3],
        ]) as usize;
        offset += 4;

        ima_measurement = Some(std::str::from_utf8(&input[offset..offset + ima_len]).unwrap());
        offset += ima_len;
    } else {
        ima_measurement = None;
    }

    let tpm_pcr10_attestation: Option<Tpm>;
    if api_opt == ApiOpt::SevTpm {
        tpm_pcr10_attestation = Some(Tpm::from_bytes(&input[offset..]));
    } else {
        tpm_pcr10_attestation = None;
    }

    Parsed {
        api_opt,
        nonce,
        raw_sev_attestation,
        vek_der_chain,
        ima_measurement,
        tpm_pcr10_attestation,
    }
}

fn sha2_der(der: &[u8]) -> Vec<u8> {
    let mut sha2_hasher = Sha256::new();
    sha2_hasher.update(der);
    sha2_hasher.finalize().to_vec()
}

#[derive(Debug)]
pub struct DecodedOutput {
    pub sev_snp_attestation: DecodedSevAttestation,
    pub tpm_attestation: Option<DecodedTpmAttestation>,
    pub nonce: Vec<u8>,
    pub ima_measurement_log_content: Option<String>,
}

#[derive(Debug)]
pub struct DecodedSevAttestation {
    pub sev_att: Vec<u8>,
    pub vek_der: Vec<u8>,
}

#[derive(Debug)]
pub struct DecodedTpmAttestation {
    pub tpm_quote: Vec<u8>,
    pub tpm_raw_sig: Vec<u8>,
    pub ak_der: Vec<u8>,
    pub ek_der: Option<Vec<u8>>,
    pub pcr_value: Vec<u8>,
}

impl DecodedOutput {
    pub fn decode_output(output: Output) -> Self {
        let nonce = if let Some(n) = output.nonce {
            BASE64_STANDARD.decode(n).unwrap()
        } else {
            vec![0]
        };
        let sev_snp_attestation = DecodedSevAttestation {
            sev_att: BASE64_STANDARD
                .decode(output.sev_snp.attestation_report)
                .unwrap(),
            vek_der: BASE64_STANDARD.decode(output.sev_snp.vek_cert).unwrap(),
        };

        let ima_measurement_bytes = if let Some(ima_encoded) = output.ima_measurement {
            BASE64_STANDARD.decode(ima_encoded).unwrap()
        } else {
            vec![]
        };

        let ima_measurement_log_content = if ima_measurement_bytes.len() > 0 {
            Some(String::from(from_utf8(&ima_measurement_bytes).unwrap()))
        } else {
            None
        };

        let tpm_attestation = if let Some(tpm) = output.tpm {
            let ek_der = if let Some(ek) = tpm.ek_cert {
                Some(BASE64_STANDARD.decode(ek).unwrap())
            } else {
                None
            };
            Some(DecodedTpmAttestation {
                tpm_quote: BASE64_STANDARD.decode(tpm.quote).unwrap(),
                tpm_raw_sig: BASE64_STANDARD.decode(tpm.raw_sig).unwrap(),
                ak_der: BASE64_STANDARD.decode(tpm.ak_cert).unwrap(),
                ek_der,
                pcr_value: BASE64_STANDARD
                    .decode(tpm.pcrs.pcrs.get(&N(10)).expect("Missing PCR10 value"))
                    .unwrap(),
            })
        } else {
            None
        };

        DecodedOutput {
            sev_snp_attestation,
            tpm_attestation,
            nonce,
            ima_measurement_log_content,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct Output {
    pub sev_snp: SevSnp,
    pub tpm: Option<AgentReportTpm>,
    pub ima_measurement: Option<String>,
    pub nonce: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct SevSnp {
    pub attestation_report: String,
    pub vek_cert: String,
}

#[derive(Debug, Deserialize)]
pub struct AgentReportTpm {
    pub quote: String,
    pub raw_sig: String,
    pub pcrs: Pcrs,
    pub ak_cert: String,
    pub ek_cert: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct Pcrs {
    pub hash: u32,
    // https://github.com/serde-rs/json/issues/372
    pub pcrs: Map<N, String>,
}

#[derive(Debug, PartialEq, PartialOrd)]
pub struct N(u32);

impl Eq for N {}
impl Ord for N {
    fn cmp(&self, other: &N) -> Ordering {
        match self.partial_cmp(&other) {
            Some(ord) => ord,
            None => unreachable!(),
        }
    }
}

impl<'de> Deserialize<'de> for N {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let val = s.parse::<u32>();
        match val {
            Ok(v) => Ok(N(v)),
            Err(_) => Err(de::Error::custom("Failed to parse u32 value")),
        }
    }
}

/// The serialization of the Journal varies by api_opt
/// Beginning with STANDARD_JOURNAL
/// STANDARD_JOURNAL = (u8 ApiOpt) || (u8 processor_model_enum) || (u32 sev_attestation_report_len) || (u8[] sev_attestation) || (u8[32] sev_ark_hash)
/// A STANDARD_JOURNAL is simply returned if api_opt == ApiOpt::Sev || api_opt == ApiOpt::SevIma
/// Both the nonce and ima_log can be verified against the value contained in the SEV Attestation Report
/// If a Journal has an api_opt == ApiOpt::SevTpm, the SEV_TPM_JOURNAL is encoded instead.
/// SEV_TPM_JOURNAL = STANDARD_JOURNAL || (u32 tpm_quote_len) || (u8[] tpm_quote) || (u16 PCR_SHA_ALGO) || (u8[] pcr10) || (u8[32] aik_root_hash || (u8[32] ek_root_hash_optional)
#[derive(Debug)]
pub struct Journal {
    pub api_opt: ApiOpt,
    pub processor_model: ProcType,
    pub sev_attestation_report: AttestationReport,
    pub vek_root_hash: [u8; 32],
    pub tpm_quote: Option<TPMSAttest>,
    pub pcr10_hash_algo: Option<u16>,
    pub pcr10_value: Option<Vec<u8>>,
    pub tpm_aik_root_hash: Option<[u8; 32]>,
    pub tpm_ek_root_hash: Option<[u8; 32]>,
}

impl Journal {
    pub fn from_bytes(raw: &[u8]) -> Journal {
        let mut offset = 0usize;
        let api_opt = ApiOpt::from_bytes(raw[0]);
        offset += 1;

        let processor_model = ProcType::from_u8(&raw[1]);
        offset += 1;

        let sev_len = u32::from_be_bytes([
            raw[offset],
            raw[offset + 1],
            raw[offset + 2],
            raw[offset + 3],
        ]) as usize;
        offset += 4;

        let mut raw_sev_attestation = Vec::with_capacity(sev_len);
        raw_sev_attestation.extend_from_slice(&raw[offset..offset + sev_len]);
        offset += sev_len;

        let mut vek_root_hash = [0u8; 32];
        vek_root_hash.copy_from_slice(&raw[offset..offset + 32]);
        offset += 32;

        let mut raw_tpm_quote: Vec<u8> = Vec::new();
        let pcr10_hash_algo: Option<u16>;
        let pcr10_value: Option<Vec<u8>>;
        let tpm_aik_root_hash: Option<[u8; 32]>;
        let tpm_ek_root_hash: Option<[u8; 32]>;
        if offset < raw.len() {
            let quote_len = u32::from_be_bytes([
                raw[offset],
                raw[offset + 1],
                raw[offset + 2],
                raw[offset + 3],
            ]) as usize;
            offset += 4;

            raw_tpm_quote.extend_from_slice(&raw[offset..offset + quote_len]);
            offset += quote_len;

            pcr10_hash_algo = Some(u16::from_be_bytes([raw[offset], raw[offset + 1]]));
            offset += 2;

            let pcr10_value_len: usize = match pcr10_hash_algo.unwrap() {
                TPM_ALG_SHA1 => 20,
                TPM_ALG_SHA256 => 32,
                _ => panic!("Unknown PCR10 hash algorithm"),
            };
            pcr10_value = Some(raw[offset..offset + pcr10_value_len].to_vec());
            offset += pcr10_value_len;

            let mut aik_root_hash = [0u8; 32];
            aik_root_hash.copy_from_slice(&raw[offset..offset + 32]);
            offset += 32;
            tpm_aik_root_hash = Some(aik_root_hash);

            if offset < raw.len() {
                let mut ek_root_hash = [0u8; 32];
                ek_root_hash.copy_from_slice(&raw[offset..offset + 32]);
                offset += 32;
                tpm_ek_root_hash = Some(ek_root_hash);
            } else {
                tpm_ek_root_hash = None;
            }
        } else {
            pcr10_hash_algo = None;
            pcr10_value = None;
            tpm_aik_root_hash = None;
            tpm_ek_root_hash = None;
        }

        assert!(offset == raw.len());

        let sev_attestation_report = AttestationReport::from_bytes(&raw_sev_attestation);
        let tpm_quote: Option<TPMSAttest>;
        if raw_tpm_quote.len() > 0 {
            tpm_quote = Some(TPMSAttest::from_bytes(&raw_tpm_quote));
        } else {
            tpm_quote = None;
        }

        Journal {
            api_opt,
            processor_model,
            sev_attestation_report,
            vek_root_hash,
            tpm_quote,
            pcr10_hash_algo,
            pcr10_value,
            tpm_aik_root_hash,
            tpm_ek_root_hash,
        }
    }
}
