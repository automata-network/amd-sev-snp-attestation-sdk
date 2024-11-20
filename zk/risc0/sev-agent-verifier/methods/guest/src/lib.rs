pub mod utils;

use utils::*;
use x509_verifier_rust_crypto::sha2::{Digest, Sha256};
use sev_snp_lib::types::ProcType;

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