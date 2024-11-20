pub mod read;
pub mod write;
use alloy::sol;

pub type InputBytesType = sol!(bytes[]);

sol! {
    #[allow(missing_docs)]
    #[sol(rpc)]
    KDS,
    "artifacts/KDS.json"
}

use sev_snp_lib::types::CertType as RustCertType;
type SolidityCertType = u8;

fn cert_type_to_solidity_enum(cert_type: &RustCertType) -> SolidityCertType {
    match cert_type {
        RustCertType::VCEK => {
            0
        },
        RustCertType::VLEK => {
            1
        },
        RustCertType::ASK => {
            2
        },
        RustCertType::ARK => {
            3
        },
        _ => panic!("Not supported by Solidity")
    }
}