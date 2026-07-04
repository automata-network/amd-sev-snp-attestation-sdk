// Override the crates by the precompiles

#[cfg(feature = "pico")]
pub extern crate sha2_pico as sha2;
#[cfg(all(feature = "risc0", not(feature = "sp1"), not(feature = "pico")))]
pub extern crate sha2_risc0 as sha2;
#[cfg(all(feature = "sp1", not(feature = "pico")))]
pub extern crate sha2_sp1 as sha2;
#[cfg(all(not(feature = "sp1"), not(feature = "risc0"), not(feature = "pico")))]
pub use sha2;

#[cfg(all(feature = "risc0_unstable", not(feature = "sp1")))]
pub extern crate p256_risc0 as p256;
#[cfg(feature = "sp1")]
pub extern crate p256_sp1 as p256;
#[cfg(all(not(feature = "sp1"), not(feature = "risc0_unstable")))]
pub use p256;

#[cfg(all(feature = "risc0_rsa", not(feature = "sp1_rsa")))]
pub extern crate rsa_risc0 as rsa;
#[cfg(feature = "sp1_rsa")]
pub extern crate rsa_sp1 as rsa;
#[cfg(all(not(feature = "sp1_rsa"), not(feature = "risc0_rsa")))]
pub use rsa;

pub use p384;

mod cert;
pub mod constants;
pub use cert::*;
mod sign;
pub use sign::*;

// re-exports
pub use x509_parser;

#[cfg(test)]
mod tests {
    use crate::{pem_to_der, CertChain};
    use x509_parser::prelude::*;

    #[test]
    fn test_short_sig() {
        let certs = read_cert_chain_json("short_sig");
        let cert_chain = CertChain::parse_rev(&certs).unwrap();
        assert!(cert_chain.verify_chain(0).unwrap(), "verification failed");
    }

    fn read_cert_chain_json(name: &str) -> Vec<Vec<u8>> {
        let path = format!("./samples/{}.json", name);
        let buf = std::fs::read(path).unwrap();
        let certs: Vec<String> = serde_json::from_slice(&buf).unwrap();
        let certs = certs
            .iter()
            .map(|n| hex::decode(n.trim_start_matches("0x")).unwrap())
            .collect::<Vec<_>>();
        certs
    }

    #[test]
    fn test_apple_ios_der_ecdsa() {
        let certs = read_cert_chain_json("apple_ios_der_ec");
        let cert_chain = CertChain::parse_rev(&certs).unwrap();
        assert!(cert_chain.verify_chain(0).unwrap(), "verification failed");
    }

    #[test]
    fn test_azure_snp_vek_cert() {
        let certs = read_cert_chain_json("azure_snp_vek_cert");
        let cert_chain = CertChain::parse_rev(&certs).unwrap();
        assert!(cert_chain.verify_chain(0).unwrap(), "verification failed");
    }

    #[test]
    fn test_gcp_tdx_tpm_cert() {
        let certs = read_cert_chain_json("gcp_tdx_tpm_cert");
        let cert_chain = CertChain::parse_rev(&certs).unwrap();
        assert!(cert_chain.verify_chain(0).unwrap(), "verification failed");
    }

    #[test]
    fn test_gcp_snp_tpm_cert() {
        let certs = read_cert_chain_json("gcp_snp_tpm_cert");
        let cert_chain = CertChain::parse_rev(&certs).unwrap();
        assert!(cert_chain.verify_chain(1).unwrap());
    }

    #[test]
    fn test_gcp_snp_vek_cert() {
        let certs = read_cert_chain_json("gcp_snp_vek_cert");
        let cert_chain = CertChain::parse_rev(&certs).unwrap();
        assert!(cert_chain.verify_chain(0).unwrap(), "verification failed");
    }

    #[test]
    fn test_android_pem_chain() {
        let pem_path: &str = "./samples/android-attestation.pem";
        let pem_chain_data = std::fs::read(pem_path).expect("PEM file not found");
        let der_chain = pem_to_der(&pem_chain_data).unwrap();
        let cert_chain = CertChain::parse_rev(&der_chain).unwrap();
        assert!(cert_chain.verify_chain(0).unwrap(), "verification failed");
    }

    #[test]
    fn test_vlek_ca_pem_chain() {
        let pem_path: &str = "./samples/vlek_milan_cert_chain.pem";
        let pem_chain_data = std::fs::read(pem_path).expect("PEM file not found");
        let der_chain = pem_to_der(&pem_chain_data).unwrap();
        let cert_chain = CertChain::parse_rev(&der_chain).unwrap();
        assert!(cert_chain.verify_chain(0).unwrap(), "verification failed");
    }

    #[test]
    fn test_vcek_chain() {
        let ca_pem_path: &str = "./samples/vcek_milan_cert_chain.pem";
        let ca_pem_chain_data = std::fs::read(ca_pem_path).expect("PEM file not found");

        let vcek_der_path: &str = "./samples/vcek.der";
        let vcek_der = std::fs::read(vcek_der_path).expect("VCEK DER not found");

        let mut der_chain = pem_to_der(&ca_pem_chain_data).unwrap();
        der_chain.insert(0, vcek_der);

        let cert_chain = CertChain::parse_rev(&der_chain).unwrap();
        assert!(cert_chain.verify_chain(0).unwrap(), "verification failed");
    }
}
