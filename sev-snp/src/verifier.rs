use asn1_rs::Oid;
use openssl::{ecdsa::EcdsaSig, sha::Sha384};
use sev::certs::snp::{Certificate, Verifiable};
use sev::firmware::{guest::AttestationReport, host::CertType};
use x509_parser::{
    self, certificate::X509Certificate, prelude::FromDer, prelude::X509Extension, x509::X509Name,
};

use crate::certs::CertificateChain;
use crate::error::{Result, SevSnpError};

pub mod snp_oid {
    use asn1_rs::{oid, Oid};

    pub const BOOTLOADER: Oid = oid!(1.3.6 .1 .4 .1 .3704 .1 .3 .1);
    pub const TEE: Oid = oid!(1.3.6 .1 .4 .1 .3704 .1 .3 .2);
    pub const SNP: Oid = oid!(1.3.6 .1 .4 .1 .3704 .1 .3 .3);
    pub const UCODE: Oid = oid!(1.3.6 .1 .4 .1 .3704 .1 .3 .8);
    pub const HWID: Oid = oid!(1.3.6 .1 .4 .1 .3704 .1 .4);
}

pub struct Verifier<'a> {
    cert_chain: &'a CertificateChain,
    attestation_report: &'a AttestationReport,
}

impl<'a> Verifier<'a> {
    pub fn new(
        cert_chain: &'a CertificateChain,
        attestation_report: &'a AttestationReport,
    ) -> Self {
        Verifier {
            cert_chain,
            attestation_report,
        }
    }

    /// Verify that the attestation report is valid.
    /// This involves checking the CA used to sign the VEK,
    /// then checking that information in the VEK matches with the report itself.
    pub fn verify(&self) -> Result<()> {
        self.verify_cert_chain()?;
        self.verify_attestation_report()?;
        Ok(())
    }

    fn verify_cert_chain(&self) -> Result<()> {
        // ARK should self sign itself, because it is the ROOT CA key.
        (&self.cert_chain.ark_cert, &self.cert_chain.ark_cert).verify()?;

        // ASK should be signed by ARK
        (&self.cert_chain.ark_cert, &self.cert_chain.ask_cert).verify()?;

        // VEK should be signed by ASK
        (&self.cert_chain.ask_cert, &self.cert_chain.vek_cert).verify()?;

        Ok(())
    }

    fn verify_attestation_report(&self) -> Result<()> {
        let vek_der = &self.cert_chain.vek_cert.to_der()?;
        let (_, vek_x509) = X509Certificate::from_der(&vek_der)?;

        self.verify_attestation_tcb(&vek_x509, &self.attestation_report)?;
        self.verify_attestation_signature(&self.cert_chain.vek_cert, &self.attestation_report)?;
        Ok(())
    }

    fn verify_attestation_tcb(
        &self,
        vek_x509: &X509Certificate,
        report: &AttestationReport,
    ) -> Result<()> {
        // Collect extensions from VEK
        let extensions: std::collections::HashMap<Oid, &X509Extension> =
            vek_x509.extensions_map()?;
        // Get the cert type: either VECK or VLEK
        let cert_type: CertType = parse_common_name(vek_x509.subject())?;

        // Check bootloaders
        if let Some(cert_bl) = extensions.get(&snp_oid::BOOTLOADER) {
            if !check_cert_bytes(cert_bl, &report.reported_tcb.bootloader.to_le_bytes())? {
                return Err(SevSnpError::X509(
                    "Attestation Report TCB Boot Loader and Certificate Boot Loader do not match!"
                        .to_string(),
                ));
            }
        }

        // Check TEE information
        if let Some(cert_tee) = extensions.get(&snp_oid::TEE) {
            if !check_cert_bytes(cert_tee, &report.reported_tcb.tee.to_le_bytes())? {
                return Err(SevSnpError::X509(
                    "Attestation Report TCB TEE and Certificate TEE do not match!".to_string(),
                ));
            }
        }

        // Check SNP information
        if let Some(cert_snp) = extensions.get(&snp_oid::SNP) {
            if !check_cert_bytes(cert_snp, &report.reported_tcb.snp.to_le_bytes())? {
                return Err(SevSnpError::X509(
                    "Attestation Report TCB SNP and Certificate SNP do not match!".to_string(),
                ));
            }
        }

        // Check Microcode information
        if let Some(cert_ucode) = extensions.get(&snp_oid::UCODE) {
            if !check_cert_bytes(cert_ucode, &report.reported_tcb.microcode.to_le_bytes())? {
                return Err(SevSnpError::X509(
                    "Attestation Report TCB Microcode and Certificate Microcode do not match!"
                        .to_string(),
                ));
            }
        }

        // Check HWID information (only for VCEK)
        if cert_type == CertType::VCEK {
            if let Some(cert_hwid) = extensions.get(&snp_oid::HWID) {
                if !check_cert_bytes(cert_hwid, &report.chip_id)? {
                    return Err(SevSnpError::X509(
                        "Attestation Report TCB ID and Certificate ID do not match!".to_string(),
                    ));
                }
            }
        }

        Ok(())
    }

    fn verify_attestation_signature(
        &self,
        vek: &Certificate,
        report: &AttestationReport,
    ) -> Result<()> {
        let vek_pubkey = vek.public_key()?.ec_key()?;

        // Get attestation report signature
        let signature = EcdsaSig::try_from(&report.signature)?;
        let signed_bytes = &bincode::serialize(report)?[0x0..0x2A0];

        let mut hasher: Sha384 = Sha384::new();
        hasher.update(signed_bytes);

        let msg_digest: [u8; 48] = hasher.finish();

        // Verify attestation report signature
        if !signature.verify(msg_digest.as_ref(), vek_pubkey.as_ref())? {
            return Err(SevSnpError::SSL(
                "VEK did not sign the Attestation Report!".to_string(),
            ));
        }

        Ok(())
    }
}

/// Check the cert extension byte to value
pub fn check_cert_bytes(ext: &X509Extension, val: &[u8]) -> Result<bool> {
    match ext.value[0] {
        // Integer
        0x2 => {
            if ext.value[1] != 0x1 && ext.value[1] != 0x2 {
                return Err(SevSnpError::X509(
                    "check_cert_bytes: Invalid integer encountered!".to_string(),
                ));
            } else if let Some(byte_value) = ext.value.last() {
                return Ok(byte_value == &val[0]);
            } else {
                return Ok(false);
            }
        }
        // Octet String
        0x4 => {
            if ext.value[1] != 0x40 {
                return Err(SevSnpError::X509(
                    "check_cert_bytes: Invalid octet length encountered!".to_string(),
                ));
            }
            if ext.value[2..].len() != 0x40 {
                return Err(SevSnpError::X509(
                    "check_cert_bytes: Invalid number of bytes encountered!".to_string(),
                ));
            }
            if val.len() != 0x40 {
                return Err(SevSnpError::X509(
                    "check_cert_bytes: Invalid certificate harward id length encountered!"
                        .to_string(),
                ));
            }

            return Ok(&ext.value[2..] == val);
        }
        // Legacy and others.
        _ => {
            // Old VCEK without x509 DER encoding, might be deprecated in the future.
            if ext.value.len() == 0x40 && val.len() == 0x40 {
                return Ok(ext.value == val);
            }
        }
    }
    Err(SevSnpError::X509(
        "check_cert_bytes: Invalid type encountered!".to_string(),
    ))
}

/// Retrieve Cert Type from X509Name field.
pub fn parse_common_name(field: &X509Name) -> Result<CertType> {
    if let Some(val) = field
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
    {
        match val.to_uppercase() {
            x if x.contains("ARK") => Ok(CertType::ARK),
            x if x.contains("ASK") => Ok(CertType::ASK),
            x if x.contains("VCEK") => Ok(CertType::VCEK),
            x if x.contains("VLEK") => Ok(CertType::VLEK),
            x if x.contains("CRL") => Ok(CertType::CRL),
            _ => Err(SevSnpError::X509(
                "Unknown certificate type encountered!".to_string(),
            )),
        }
    } else {
        Err(SevSnpError::X509(
            "Certificate Subject Common Name is Unknown!".to_string(),
        ))
    }
}
