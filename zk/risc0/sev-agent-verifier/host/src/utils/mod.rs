pub mod parser;
pub mod serializer;
pub mod deserializer;
pub mod certs;

use parser::Output;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ApiOpt {
    Sev,
    SevIma,
    SevTpm
}

impl ApiOpt {
    pub fn from_output(output: &Output) -> Self {
        if output.ima_measurement.is_some() {
            if output.tpm.is_some() {
                ApiOpt::SevTpm
            } else {
                ApiOpt::SevIma
            }
        } else {
            ApiOpt::Sev
        }
    }

    pub fn from_bytes(raw: u8) -> Self {
        match raw {
            0 => ApiOpt::Sev,
            1 => ApiOpt::SevIma,
            2 => ApiOpt::SevTpm,
            _ => panic!("Unknown ApiOpt"),
        }
    }

    pub fn to_bytes(&self) -> u8 {
        match self {
            ApiOpt::Sev => 0,
            ApiOpt::SevIma => 1,
            ApiOpt::SevTpm => 2
        }
    }
}

#[derive(Debug)]
pub struct Tpm {
    pub quote: Vec<u8>,
    pub signature: Vec<u8>,
    pub pcr10_hash_algo: u16,
    pub pcr10_value: Vec<u8>,
    pub ak_der_chain: Vec<Vec<u8>>,
    pub ek_der_chain: Option<Vec<Vec<u8>>>
}