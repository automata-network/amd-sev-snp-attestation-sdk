use openssl::x509::X509;
use sev::firmware::host::CertType;
use sev::{certs::snp::Certificate, firmware::guest::AttestationReport};
use std::io::Read;

use crate::certs::CertificateChain;
use crate::cpu::ProcType;
use crate::error::Result;
use crate::utils::CertTypeExt;
/// Struct to represent the AMD Key Distribution Service.
pub struct KDS {}

impl KDS {
    pub fn new() -> Self {
        KDS {}
    }

    /// Fetch ARK, ASK and VCEK certificates from the KDS and returns it as a CertificateChain
    pub fn fetch_vcek_cert_chain(
        &self,
        processor_model: &ProcType,
        report: &AttestationReport,
    ) -> Result<CertificateChain> {
        let ask_ark_certs = self.fetch_ca(processor_model, CertType::VCEK)?;
        let vcek_cert = self.fetch_vcek(processor_model, report)?;

        Ok(CertificateChain::new(
            ask_ark_certs[1].clone().into(),
            ask_ark_certs[0].clone().into(),
            vcek_cert,
        ))
    }

    /// Fetch CA certificates (ARK and ASK) from the KDS.
    /// Also takes as input the VLEK cert, and returns it together with CA cert as a CertificateChain
    pub fn fetch_vlek_cert_chain(
        &self,
        processor_model: &ProcType,
        vlek_cert: &Certificate,
    ) -> Result<CertificateChain> {
        let ask_ark_certs = self.fetch_ca(processor_model, CertType::VLEK)?;

        Ok(CertificateChain::new(
            ask_ark_certs[1].clone().into(),
            ask_ark_certs[0].clone().into(),
            vlek_cert.clone(),
        ))
    }

    /// Fetch ARK and ASK certificates from the KDS
    ///
    /// Returns:
    /// - Vec<X509>: [ASK cert, ARK cert]
    pub fn fetch_ca(&self, processor_model: &ProcType, cert_type: CertType) -> Result<Vec<X509>> {
        // https://kdsintf.amd.com/vcek/v1/<PROCESSOR_CODE_NAME>/cert_chain
        let url: String = format!(
            "https://kdsintf.amd.com/{}/v1/{}/cert_chain",
            cert_type.string().to_lowercase(),
            processor_model.to_kds_url()
        );

        let rsp = ureq::get(&url).call()?;

        let mut bytes: Vec<u8> = Vec::with_capacity(8192);
        rsp.into_reader().take(8192).read_to_end(&mut bytes)?;

        Ok(X509::stack_from_pem(&bytes)?)
    }

    /// Fetch ARK and ASK certificates as DER from the KDS
    ///
    /// Returns:
    /// - Vec<u8>: [ASK cert, ARK cert]
    pub fn fetch_ca_der(
        &self,
        processor_model: &ProcType,
        cert_type: CertType,
    ) -> Result<Vec<Vec<u8>>> {
        // https://kdsintf.amd.com/vcek/v1/<PROCESSOR_CODE_NAME>/cert_chain
        let certs = self.fetch_ca(processor_model, cert_type)?;
        let mut output: Vec<Vec<u8>> = Vec::<Vec<u8>>::new();
        for cert in certs {
            let bytes = cert.to_der()?;
            output.push(bytes);
        }

        Ok(output)
    }

    /// Fetch VCEK certificate as Certificate object from the KDS
    ///
    /// Returns: Certificate
    pub fn fetch_vcek(
        &self,
        processor_model: &ProcType,
        report: &AttestationReport,
    ) -> Result<Certificate> {
        let bytes = self.fetch_vcek_der(processor_model, report)?;

        Ok(Certificate::from_bytes(&bytes)?)
    }

    /// Fetch VCEK certificate as DER from the KDS
    ///
    /// Returns: Vec<u8>
    pub fn fetch_vcek_der(
        &self,
        processor_model: &ProcType,
        report: &AttestationReport,
    ) -> Result<Vec<u8>> {
        // Use attestation report to get hw_id for URL
        let hw_id: String = hex::encode(&report.chip_id);

        let url: String = format!(
            "https://kdsintf.amd.com/vcek/v1/{}/\
    {hw_id}?blSPL={:02}&teeSPL={:02}&snpSPL={:02}&ucodeSPL={:02}",
            processor_model.to_kds_url(),
            &report.reported_tcb.bootloader,
            &report.reported_tcb.tee,
            &report.reported_tcb.snp,
            &report.reported_tcb.microcode
        );

        // Retrieve VCEK from KDS in DER format
        let rsp = ureq::get(&url).call()?;

        let mut bytes: Vec<u8> = Vec::with_capacity(4096);
        rsp.into_reader().take(4096).read_to_end(&mut bytes)?;
        Ok(bytes)
    }
}
