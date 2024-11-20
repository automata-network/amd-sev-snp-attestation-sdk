use risc0_zkvm::guest::env;
use std::io::Read;

use sev_agent_verifier_guest::{deserialize_guest_input, utils::ApiOpt};
use sev_snp_lib::{
    attestation::AttestationReport,
    get_processor_model_from_vek,
    verify::{verify_attestation_signature, verify_attestation_tcb},
};
use tpm_lib::{
    tpm::{FromBytes, TPMSAttest},
    verify_tpm_quote_and_pcr10,
};
use x509_verifier_rust_crypto::{
    sha2::{Digest, Sha256},
    verify_x509_chain,
    x509_parser::prelude::*,
};

fn main() {
    // Read the input
    let mut input_bytes = Vec::<u8>::new();
    env::stdin().read_to_end(&mut input_bytes).unwrap();

    let parsed = deserialize_guest_input(&input_bytes);

    // Step 1: Verify VEK Chain, then verify SEV Attestation Report
    let vek_cert_chain = parse_der_chain(&parsed.vek_der_chain);
    let vek_verified = verify_x509_chain(&vek_cert_chain);
    assert!(vek_verified, "Failed to verify VEK Certificate chain");

    let sev_attestation_report = AttestationReport::from_bytes(&parsed.raw_sev_attestation);

    let verified_sev_attestation_sig =
        verify_attestation_signature(&vek_cert_chain[0], &sev_attestation_report);
    assert!(
        verified_sev_attestation_sig,
        "Failed to verify SEV Attestation Signature"
    );

    let vek_type = sev_attestation_report.get_signing_cert_type();
    verify_attestation_tcb(vek_type, &vek_cert_chain[0], &sev_attestation_report);

    // Step 2: Verify TPM Quote, PCR10 Value and the AIK Certificate Chain
    if parsed.api_opt == ApiOpt::SevTpm {
        let unwrapped_tpm_pcr10_attestation = parsed.tpm_pcr10_attestation.as_ref().unwrap();
        let tpm_quote_and_pcr10_verified = verify_tpm_quote_and_pcr10(
            &unwrapped_tpm_pcr10_attestation.quote,
            &unwrapped_tpm_pcr10_attestation.signature,
            &unwrapped_tpm_pcr10_attestation.pcr10_value,
            &parsed.ima_measurement.unwrap(),
            &unwrapped_tpm_pcr10_attestation.ak_der_chain[0],
        )
        .is_ok();
        assert!(
            tpm_quote_and_pcr10_verified,
            "Failed to verify TPM and PCR10 values"
        );

        let aik_cert_chain = parse_der_chain(&unwrapped_tpm_pcr10_attestation.ak_der_chain);
        let aik_verified = verify_x509_chain(&aik_cert_chain);
        assert!(aik_verified, "Failed to verify AIK Certificate Chain");

        if let Some(ek_der) = unwrapped_tpm_pcr10_attestation.ek_der_chain.as_ref() {
            let ek_cert_chain = parse_der_chain(ek_der);
            let ek_verified = verify_x509_chain(&ek_cert_chain);
            assert!(ek_verified, "Failed to verify EK Certificate Chain");
        }
    }

    // Step 3: Verify the nonce
    let mut sev_expected_data: Vec<u8> = Vec::with_capacity(64);
    sev_expected_data.extend_from_slice(&[0u8; 32]);

    let mut sha2_hasher = Sha256::new();
    match parsed.api_opt {
        ApiOpt::Sev => {
            sha2_hasher.update(&parsed.nonce);
        }
        ApiOpt::SevIma => {
            let ima_bytes = parsed.ima_measurement.unwrap().as_bytes();
            sha2_hasher.update(ima_bytes);
            sha2_hasher.update(&parsed.nonce);
        }
        ApiOpt::SevTpm => {
            // check TPM quote data first...
            let tpms_attest =
                TPMSAttest::from_bytes(&parsed.tpm_pcr10_attestation.as_ref().unwrap().quote);
            let tpms_attest_extra_data = tpms_attest.extra_data;
            assert!(
                &parsed.nonce == &tpms_attest_extra_data,
                "TPMS Attest data does not match with nonce"
            );

            let aik_leaf_der_bytes =
                parsed.tpm_pcr10_attestation.as_ref().unwrap().ak_der_chain[0].as_slice();
            sha2_hasher.update(aik_leaf_der_bytes);
            sha2_hasher.update(&parsed.nonce);
        }
    }

    sev_expected_data.extend_from_slice(sha2_hasher.finalize().as_slice());
    assert!(
        sev_expected_data == sev_attestation_report.report_data,
        "SEV Report Data does not match with nonce"
    );

    // Write the Journal
    let processor_model = get_processor_model_from_vek(vek_type, &vek_cert_chain[0]);
    let journal: Vec<u8> = parsed.serialize_journal(processor_model);
    env::commit_slice(&journal);
}

fn parse_der_chain<'a>(der_chain: &'a Vec<Vec<u8>>) -> Vec<X509Certificate<'a>> {
    let mut cert_chain_vec: Vec<X509Certificate> = Vec::with_capacity(der_chain.len());
    for der in der_chain.iter() {
        match parse_x509_certificate(der) {
            Ok((_, cert)) => cert_chain_vec.push(cert),
            Err(e) => panic!("Error parsing certificate: {:?}", e),
        }
    }
    cert_chain_vec
}
