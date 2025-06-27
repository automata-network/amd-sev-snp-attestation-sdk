use openssl::pkey::{PKey, Public};
use openssl::x509::X509;
use std::io::{Error, ErrorKind, Result};

pub struct CertificateChain {
    /// AMD Root Key Certificate
    pub ark_cert: Certificate,
    /// AMD SEV Key Certificate
    pub ask_cert: Certificate,
    /// VEK: Either a VCEK or VLEK.
    /// VLEK: Versioned Loaded Endorsement Key (VLEK), which is issued by AMD to a cloud provider
    /// VCEK: VM Chip Endorsement Key). VCEK is unique per CPU.
    pub vek_cert: Certificate,
}

impl CertificateChain {
    pub fn new(ark_cert: Certificate, ask_cert: Certificate, vek_cert: Certificate) -> Self {
        CertificateChain {
            ark_cert,
            ask_cert,
            vek_cert,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CertFormat {
    Pem,
    Der,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Certificate(X509);

/// Wrap an X509 struct into a Certificate.
impl From<X509> for Certificate {
    fn from(x509: X509) -> Self {
        Self(x509)
    }
}

/// Unwrap the underlying X509 struct from a Certificate.
impl From<Certificate> for X509 {
    fn from(cert: Certificate) -> Self {
        cert.0
    }
}

/// Clone the underlying X509 structure from a reference to a Certificate.
impl From<&Certificate> for X509 {
    fn from(cert: &Certificate) -> Self {
        cert.0.clone()
    }
}

impl From<&X509> for Certificate {
    fn from(value: &X509) -> Self {
        Self(value.clone())
    }
}

impl From<&[X509]> for Certificate {
    /// Retrieves only the first value from the hash, ignoring all other values.
    fn from(value: &[X509]) -> Self {
        value[0].clone().into()
    }
}

impl<'a: 'b, 'b> From<&'a Certificate> for &'b X509 {
    fn from(value: &'a Certificate) -> Self {
        &value.0
    }
}

/// An interface for types that may contain entities such as
/// signatures that must be verified.
pub trait Verifiable {
    /// An output type for successful verification.
    type Output;

    /// Self-verifies signatures.
    fn verify(self) -> Result<Self::Output>;
}

/// Verify if the public key of one Certificate signs another Certificate.
impl Verifiable for (&Certificate, &Certificate) {
    type Output = ();

    fn verify(self) -> Result<Self::Output> {
        let signer: X509 = self.0.into();
        let signee: X509 = self.1.into();

        let key: PKey<Public> = signer.public_key()?;
        let signed = signee.verify(&key)?;

        match signed {
            true => Ok(()),
            false => Err(Error::new(
                ErrorKind::Other,
                "Signer certificate does not sign signee certificate",
            )),
        }
    }
}

impl Certificate {
    /// Create a Certificate from a PEM-encoded X509 structure.
    pub fn from_pem(pem: &[u8]) -> Result<Self> {
        Ok(Self(X509::from_pem(pem)?))
    }

    /// Serialize a Certificate struct to PEM.
    pub fn to_pem(&self) -> Result<Vec<u8>> {
        Ok(self.0.to_pem()?)
    }

    /// Create a Certificate from a DER-encoded X509 structure.
    pub fn from_der(der: &[u8]) -> Result<Self> {
        Ok(Self(X509::from_der(der)?))
    }

    /// Serialize a Certificate struct to DER.
    pub fn to_der(&self) -> Result<Vec<u8>> {
        Ok(self.0.to_der()?)
    }

    /// Retrieve the underlying X509 public key for a Certificate.
    pub fn public_key(&self) -> Result<PKey<Public>> {
        Ok(self.0.public_key()?)
    }

    /// Identifies the format of a certificate based upon the first twenty-seven
    /// bytes of a byte stream. A non-PEM format assumes DER format.
    pub fn identify_format(bytes: &[u8]) -> CertFormat {
        const PEM_START: &[u8] = b"-----BEGIN CERTIFICATE-----";
        match &bytes[0..27] {
            PEM_START => CertFormat::Pem,
            _ => CertFormat::Der,
        }
    }

    /// An façade method for constructing a Certificate from raw bytes.
    pub fn from_bytes(raw_bytes: &[u8]) -> Result<Self> {
        match Self::identify_format(raw_bytes) {
            CertFormat::Pem => Self::from_pem(raw_bytes),
            CertFormat::Der => Self::from_der(raw_bytes),
        }
    }
}
