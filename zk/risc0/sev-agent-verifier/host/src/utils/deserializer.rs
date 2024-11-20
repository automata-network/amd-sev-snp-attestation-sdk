use sev_snp_lib::attestation::AttestationReport;
use sev_snp_lib::types::ProcType;
use tpm_lib::constants::{TPM_ALG_SHA1, TPM_ALG_SHA256};
use tpm_lib::tpm::{FromBytes, TPMSAttest};

use super::ApiOpt;

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
