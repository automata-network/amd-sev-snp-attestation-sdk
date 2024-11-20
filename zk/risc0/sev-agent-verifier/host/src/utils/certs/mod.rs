pub mod kds;
pub mod tpm;

use x509_parser::prelude::Pem;
use reqwest::blocking::get;
use anyhow::Result;

// PEM chain to DER-encoded bytes conversion
// Provide PEM data directly to this function call
pub fn pem_to_der(pem_chain: &[u8]) -> Vec<Vec<u8>> {
    let mut der_chain: Vec<Vec<u8>> = Vec::new();

    for pem in Pem::iter_from_buffer(pem_chain) {
        let current_pem_content = pem.unwrap().contents;
        der_chain.push(current_pem_content);
    }

    der_chain
}

fn fetch_certificate(url_str: &str) -> Result<Vec<u8>> {
    let ret_data = get(url_str)?.bytes()?.to_vec();
    Ok(ret_data)
}