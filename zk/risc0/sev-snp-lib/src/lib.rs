pub mod attestation;
pub mod types;
pub mod verify;

// pub mod kds;

use x509_verifier_rust_crypto::x509_parser::prelude::*;
use types::{ProcType, CertType};

pub fn get_processor_model_from_vek(vek_type: CertType, vek_cert: &X509Certificate) -> ProcType {
    let vek_issuer = vek_cert.issuer();
    let vek_issuer_name = (&vek_issuer).iter_common_name().next().unwrap().as_str().unwrap();
    let vek_issuer_name_vec: Vec<&str> = vek_issuer_name.split("-").collect();

    let ret: ProcType;
    match vek_type {
        CertType::VCEK => {
            let processor_model = vek_issuer_name_vec[1];
            ret = ProcType::from_str(processor_model);
        },
        CertType::VLEK => {
            let vlek = vek_issuer_name_vec[1];
            assert!(vlek == "VLEK", "Not a valid VLEK issuer name");
            let processor_model = vek_issuer_name_vec[2];
            ret = ProcType::from_str(processor_model);
        },
        _ => panic!("Unknown VEK Cert type")
    }

    ret
}