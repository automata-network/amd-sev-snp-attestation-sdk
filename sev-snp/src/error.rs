use std::fmt::Display;

use coco_provider::error::CocoError;
use x509_parser::error::X509Error;

pub type Result<T> = std::result::Result<T, SevSnpError>;

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum SevSnpError {
    Bincode(String),
    ConfigOptions(String),
    Cpu(String),
    DerivedKey(String),
    Firmware(String),
    Http(String),
    IO(String),
    SSL(String),
    Tpm(String),
    X509(String),
    Unknown,
}

impl Display for SevSnpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SevSnpError::Bincode(msg) => write!(f, "Bincode: {}", msg),
            SevSnpError::ConfigOptions(msg) => write!(f, "ConfigOptions: {}", msg),
            SevSnpError::Cpu(msg) => write!(f, "CPU: {}", msg),
            SevSnpError::DerivedKey(msg) => write!(f, "DerivedKey: {}", msg),
            SevSnpError::Firmware(msg) => write!(f, "Firmware: {}", msg),
            SevSnpError::Http(msg) => write!(f, "HTTP: {}", msg),
            SevSnpError::IO(msg) => write!(f, "IO: {}", msg),
            SevSnpError::SSL(msg) => write!(f, "SSL: {}", msg),
            SevSnpError::Tpm(msg) => write!(f, "TPM: {}", msg),
            SevSnpError::X509(msg) => write!(f, "X509: {}", msg),
            SevSnpError::Unknown => write!(f, "Unknown"),
        }
    }
}

impl std::error::Error for SevSnpError {}

impl From<Box<bincode::ErrorKind>> for SevSnpError {
    fn from(err: Box<bincode::ErrorKind>) -> Self {
        SevSnpError::Bincode(format!("{err}"))
    }
}

impl From<std::io::Error> for SevSnpError {
    fn from(err: std::io::Error) -> Self {
        SevSnpError::IO(format!("{err}"))
    }
}

impl From<openssl::error::ErrorStack> for SevSnpError {
    fn from(err: openssl::error::ErrorStack) -> Self {
        SevSnpError::SSL(format!("{err}"))
    }
}

impl From<X509Error> for SevSnpError {
    fn from(err: x509_parser::error::X509Error) -> Self {
        SevSnpError::X509(format!("{err}"))
    }
}

impl From<x509_parser::nom::Err<X509Error>> for SevSnpError {
    fn from(err: x509_parser::nom::Err<X509Error>) -> Self {
        SevSnpError::X509(format!("{err}"))
    }
}

impl From<ureq::Error> for SevSnpError {
    fn from(err: ureq::Error) -> Self {
        SevSnpError::Http(format!("{err}"))
    }
}

impl From<&str> for SevSnpError {
    fn from(err: &str) -> Self {
        SevSnpError::Firmware(err.to_string())
    }
}

impl From<CocoError> for SevSnpError {
    fn from(err: CocoError) -> Self {
        SevSnpError::Firmware(format!("{:?}", err))
    }
}
