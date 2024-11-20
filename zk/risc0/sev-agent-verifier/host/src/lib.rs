pub mod utils;
pub mod constants;
pub mod chain;
pub mod code;

use crate::code::sev_guest::SEV_AGENT_VERIFIER_GUEST_ELF;

use anyhow::Result;
use risc0_zkvm::{default_prover, ExecutorEnv, ProverOpts, Receipt, compute_image_id};

pub fn prove_input_and_get_journal(input: &[u8], prove_opt: ProverOpts) -> Result<Receipt> {
    let env = ExecutorEnv::builder().write_slice(&input).build()?;
    let receipt = default_prover()
        .prove_with_opts(env, SEV_AGENT_VERIFIER_GUEST_ELF, &prove_opt)?
        .receipt;

    receipt.verify(compute_image_id(SEV_AGENT_VERIFIER_GUEST_ELF)?)?;
    Ok(receipt)
}

pub fn prover_is_bonsai() -> bool {
    let api_url_found = std::env::var("BONSAI_API_URL").is_ok();
    let api_key_found = std::env::var("BONSAI_API_KEY").is_ok();
    let explicit = std::env::var("RISC0_PROVER").unwrap_or_else(|_| String::from(""));
    let explicit_valid = explicit.is_empty() || explicit == String::from("bonsai");
    api_key_found && api_url_found && explicit_valid
}

#[cfg(test)]
mod tests {
    use sev_snp_lib::attestation::AttestationReport;
    use utils::certs::{kds::fetch_vek_issuer_ca_pem_chain, tpm::get_tpm_cert_der_chain};

    use super::*;

    use std::{
        fs::read_to_string,
        path::PathBuf,
    };

    use crate::utils::{
        certs::pem_to_der, deserializer::Journal, parser::DecodedOutput,
        serializer::serialize_guest_input, ApiOpt, Tpm,
    };

    use x509_parser::prelude::parse_x509_certificate;

    #[test]
    fn test_sev_attestation_with_tpm() {
        let output_data = read_to_string(PathBuf::from("../../data/output.json")).unwrap();
        let output = serde_json::from_str(output_data.as_str()).unwrap();

        let api_opt = ApiOpt::from_output(&output);

        let decoded_output = DecodedOutput::decode_output(output);
        
        let raw_sev_attestation_report = decoded_output.sev_snp_attestation.sev_att;
        // let vcek_leaf_pem = read_bytes(PathBuf::from("../../data/sev/vcek.pem")).unwrap();

        let mut vek_cert_chain = Vec::new();
        vek_cert_chain.push(decoded_output.sev_snp_attestation.vek_der.clone());

        let (_, vek_leaf) = parse_x509_certificate(&vek_cert_chain[0]).unwrap();
        let vek_type =
            AttestationReport::from_bytes(&raw_sev_attestation_report).get_signing_cert_type();
        let proc_type = sev_snp_lib::get_processor_model_from_vek(vek_type, &vek_leaf);
        let vcek_ca_pem_chain = fetch_vek_issuer_ca_pem_chain(&proc_type, &vek_type).unwrap();

        vek_cert_chain = [vek_cert_chain, pem_to_der(&vcek_ca_pem_chain)].concat();

        let tpm_attestation = decoded_output.tpm_attestation.unwrap();
        let (_, ak_leaf) = parse_x509_certificate(&tpm_attestation.ak_der).unwrap();
        let mut ak_der_chain = vec![tpm_attestation.ak_der.clone()];
        ak_der_chain = [ak_der_chain, get_tpm_cert_der_chain(&ak_leaf).unwrap()].concat();

        let ek_der = tpm_attestation.ek_der.unwrap();
        let (_, ek_leaf) = parse_x509_certificate(&ek_der).unwrap();
        let mut ek_der_chain = vec![ek_der.clone()];
        ek_der_chain = [ek_der_chain, get_tpm_cert_der_chain(&ek_leaf).unwrap()].concat();

        let tpm = Tpm {
            quote: tpm_attestation.tpm_quote.clone(),
            signature: tpm_attestation.tpm_raw_sig.clone(),
            pcr10_hash_algo: tpm_lib::constants::TPM_ALG_SHA1,
            pcr10_value: tpm_attestation.pcr_value,
            ak_der_chain: ak_der_chain,
            ek_der_chain: Some(ek_der_chain),
        };

        let serialized_input = serialize_guest_input(
            api_opt,
            &decoded_output.nonce,
            &raw_sev_attestation_report,
            vek_cert_chain,
            Some(decoded_output.ima_measurement_log_content.unwrap().as_str()),
            Some(tpm),
        );

        let receipt = prove_input_and_get_journal(&serialized_input, ProverOpts::default());
        assert!(receipt.is_ok());
        println!(
            "Journal: {:?}",
            Journal::from_bytes(receipt.unwrap().journal.bytes.as_slice())
        );
    }
}
