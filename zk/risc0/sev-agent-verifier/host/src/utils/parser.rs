use base64::prelude::*;
use serde::de::{self, Deserializer};
use serde::Deserialize;
use std::cmp::Ordering;
use std::collections::BTreeMap as Map;
use std::str::from_utf8;

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
    pub vek_der: Vec<u8>
}

#[derive(Debug)]
pub struct DecodedTpmAttestation {
    pub tpm_quote: Vec<u8>,
    pub tpm_raw_sig: Vec<u8>,
    pub ak_der: Vec<u8>,
    pub ek_der: Option<Vec<u8>>,
    pub pcr_value: Vec<u8>
}

impl DecodedOutput {
    pub fn decode_output(output: Output) -> Self {
        let nonce = if let Some(n) = output.nonce {
            BASE64_STANDARD.decode(n).unwrap()
        } else {
            vec![0]
        };
        let sev_snp_attestation = DecodedSevAttestation{
            sev_att: BASE64_STANDARD.decode(output.sev_snp.attestation_report).unwrap(),
            vek_der: BASE64_STANDARD.decode(output.sev_snp.vek_cert).unwrap()
        };
        
        let ima_measurement_bytes= if let Some(ima_encoded) = output.ima_measurement {
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
            Some(DecodedTpmAttestation{
                tpm_quote: BASE64_STANDARD.decode(tpm.quote).unwrap(),
                tpm_raw_sig: BASE64_STANDARD.decode(tpm.raw_sig).unwrap(),
                ak_der: BASE64_STANDARD.decode(tpm.ak_cert).unwrap(),
                ek_der,
                pcr_value: BASE64_STANDARD
                    .decode(
                            tpm
                            .pcrs
                            .pcrs
                            .get(&N(10))
                            .expect("Missing PCR10 value"),
                    )
                    .unwrap(),
            })
        } else {
            None
        };

        DecodedOutput {
            sev_snp_attestation,
            tpm_attestation,
            nonce,
            ima_measurement_log_content
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct Output {
    pub sev_snp: SevSnp,
    pub tpm: Option<Tpm>,
    pub ima_measurement: Option<String>,
    pub nonce: Option<String>
}

#[derive(Debug, Deserialize)]
pub struct SevSnp {
    pub attestation_report: String,
    pub vek_cert: String
}

#[derive(Debug, Deserialize)]
pub struct Tpm {
    pub quote: String,
    pub raw_sig: String,
    pub pcrs: Pcrs,
    pub ak_cert: String,
    pub ek_cert: Option<String>
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
