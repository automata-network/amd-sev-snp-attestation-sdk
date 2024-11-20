// pub mod certs;
pub mod constants;
pub mod tpm;
pub(crate) type Result<T> = std::result::Result<T, std::io::Error>;

use constants::{TPM_ALG_SHA1, TPM_ALG_SHA256};
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use sha1::{Digest, Sha1};
use sha2::Sha256;
use tpm::{FromBytes, TPMSAttest, TPMUAttest};
use x509_parser::prelude::*;

pub fn verify_tpm_quote_and_pcr10(
    tpm_quote: &[u8],
    tpm_raw_sig: &[u8],
    pcr_value: &[u8],
    ima_measurement_log_content: &str,
    ak_der: &[u8],
) -> Result<()> {
    let (_, ak_cert) = X509Certificate::from_der(ak_der).unwrap();

    // verify TPM quote signature
    assert!(
        verify_tpm_quote_signature(tpm_quote, tpm_raw_sig, &ak_cert),
        "Invalid TPM Quote Signature"
    );

    // verify PCR10 value with ima logs
    let hashes = get_ima_template_hash_chain(ima_measurement_log_content);
    let parsed_quote = TPMSAttest::from_bytes(tpm_quote);
    let TPMUAttest::Quote(quote_info) = parsed_quote.attested;
    assert!(
        quote_info.count == 1,
        "Only supported one TPM quote at a time"
    );
    let mut pcr: Vec<u8>;
    match quote_info.pcr_selections[0].hash {
        TPM_ALG_SHA1 => {
            pcr = vec![0; 20];
            for hash in hashes.iter() {
                let mut sha1_hasher = Sha1::new();
                sha1_hasher.update(&pcr);
                sha1_hasher.update(&hash);
                pcr = sha1_hasher.finalize().to_vec();
            }
        }
        TPM_ALG_SHA256 => {
            pcr = vec![0; 32];
            for hash in hashes.iter() {
                let mut sha256_hasher = Sha256::new();
                sha256_hasher.update(&pcr);
                sha256_hasher.update(&hash);
                pcr = sha256_hasher.finalize().to_vec();
            }
        }
        _ => {
            panic!("Unsupported PCR hash algorithm")
        }
    }
    assert!(
        hex::encode(pcr_value) == hex::encode(&pcr),
        "IMA hash chain does not match with PCR10"
    );

    Ok(())
}

fn verify_tpm_quote_signature(
    tpm_quote: &[u8],
    tpm_raw_signature: &[u8],
    ak: &X509Certificate,
) -> bool {
    let signer_key = ak.public_key().subject_public_key.as_ref();
    let sig = convert_tpmt_sig_to_ecdsa_signature(tpm_raw_signature);
    let signature = Signature::from_bytes(sig.as_slice().try_into().unwrap()).unwrap();
    let verifying_key = VerifyingKey::from_sec1_bytes(signer_key).unwrap();
    verifying_key.verify(tpm_quote, &signature).is_ok()
}

fn convert_tpmt_sig_to_ecdsa_signature(raw_sig: &[u8]) -> Vec<u8> {
    let mut ret: Vec<u8> = Vec::with_capacity(64);
    ret.extend_from_slice(&raw_sig[6..38]);
    ret.extend_from_slice(&raw_sig[40..72]);
    ret
}

fn get_ima_template_hash_chain(ima_content: &str) -> Vec<Vec<u8>> {
    let lines: Vec<&str> = ima_content.split("\n").collect();
    let mut ret = vec![];

    for line in lines.into_iter() {
        let line_row: Vec<&str> = line.split(" ").collect();
        if line_row.len() > 1 {
            let hash = hex::decode(&line_row[1]).unwrap();
            ret.push(hash);
        }
    }

    ret
}
