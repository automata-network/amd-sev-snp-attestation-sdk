use std::fmt::Display;

use sev::error::UserApiError;
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
        write!(f, "{}", self)
    }
}

impl std::error::Error for SevSnpError {}

impl From<Box<bincode::ErrorKind>> for SevSnpError {
    fn from(err: Box<bincode::ErrorKind>) -> Self {
        SevSnpError::Bincode(format!("{err}"))
    }
}

impl From<tss_esapi::Error> for SevSnpError {
    fn from(err: tss_esapi::Error) -> Self {
        SevSnpError::Tpm(format!("{err}"))
    }
}

impl From<std::io::Error> for SevSnpError {
    fn from(err: std::io::Error) -> Self {
        SevSnpError::IO(format!("{err}"))
    }
}

impl From<UserApiError> for SevSnpError {
    fn from(err: UserApiError) -> Self {
        SevSnpError::Firmware(format!("{err}"))
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
