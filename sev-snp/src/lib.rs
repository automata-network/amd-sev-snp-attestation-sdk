mod certs;
mod cpu;
mod kds;
mod verifier;

pub mod device;
pub mod error;
pub mod key;
pub mod utils;

use certs::CertificateChain;
use kds::KDS;
use sev::certs::snp::Certificate;
use sev::firmware::guest::AttestationReport;
use sev::firmware::host::CertType;
use std::collections::HashMap;

use crate::error::{Result, SevSnpError};
use crate::utils::AttestationReportExt;

/// Indicate whether attestation verification should happen with
/// certs retrieved from SEV-SNP device or KDS or custom.
#[derive(PartialEq)]
pub enum AttestationFlow {
    Regular,
    Extended,
    Vlek,
}

pub struct SevSnp {
    is_hyperv: bool,
    kds: KDS,
    cert_device: device::Device,
}

impl SevSnp {
    pub fn new() -> Self {
        let is_hyperv = crate::utils::HyperV::present();
        let kds = KDS::new();
        // Device options does not matter when only retrieving certs from it.
        let cert_device = device::Device::default(is_hyperv);
        SevSnp {
            is_hyperv,
            kds,
            cert_device,
        }
    }

    /// Generate Derived Key using the default settings.
    ///
    /// Returns:
    /// - Ok: Derived Key as [u8;32]
    /// - Error: Problems with key generation
    pub fn get_derived_key(&self) -> Result<[u8; 32]> {
        let generator = key::DerivedKeyGenerator::default(self.is_hyperv);
        Ok(generator.get()?)
    }

    /// Generate Derived Key, but specify custom options for the key generation.
    /// When in doubt, use the default generator `get_derived_key()` instead of this.
    ///
    /// Returns:
    /// - Ok: Derived Key as [u8;32]
    /// - Error: Problems with key generation
    pub fn get_derived_key_with_options(
        &self,
        options: key::DerivedKeyOptions,
    ) -> Result<[u8; 32]> {
        let generator = key::DerivedKeyGenerator::new(options, self.is_hyperv);
        Ok(generator.get()?)
    }

    /// Get the attestation report using the default settings.
    pub fn get_attestation_report(&self) -> Result<AttestationReport> {
        let device = device::Device::default(self.is_hyperv);
        device.get_attestation_report()
    }

    /// Get the attestation report, but specify custom options for the device.
    /// When in doubt, use the default `get_attestation_report()` instead of this.
    pub fn get_attestation_report_with_options(
        &self,
        device_options: device::DeviceOptions,
    ) -> Result<AttestationReport> {
        let device = device::Device::new(device_options, self.is_hyperv);
        device.get_attestation_report()
    }

    /// Retieve certificates for the attestation report
    pub fn get_certificates(
        &self,
        report: &AttestationReport,
        flow: &AttestationFlow,
        vek_only: bool,
    ) -> Result<HashMap<String, Vec<u8>>> {
        let signer_type = report.get_signer_type()?;
        if signer_type == CertType::VLEK {
            if flow != &AttestationFlow::Vlek {
                return Err(crate::error::SevSnpError::Firmware(
                    "VLEK Flow must be used for VLEK certs.".to_string(),
                ));
            }
            // Retrieve VLEK cert from the cpu
            let mut cert_map = self.cert_device.get_certificates_der()?;
            if !vek_only {
                let ca = self
                    .kds
                    .fetch_ca_der(&cpu::ProcType::Milan, CertType::VLEK)?;
                cert_map.insert("ARK".to_string(), ca[1].clone());
                cert_map.insert("ASK".to_string(), ca[0].clone());
            }
            return Ok(cert_map);
        } else {
            if flow == &AttestationFlow::Vlek {
                return Err(crate::error::SevSnpError::Firmware(
                    "VLEK Flow can only be used for VLEK certs!".to_string(),
                ));
            } else if flow == &AttestationFlow::Extended && self.is_hyperv {
                return Err(crate::error::SevSnpError::Firmware(
                    "Extended attestation flow cannot be used with Hyper-V!".to_string(),
                ));
            }
            if flow == &AttestationFlow::Regular {
                let mut cert_map = HashMap::<String, Vec<u8>>::new();
                let processor_model = &cpu::ProcType::Milan;
                let cert = self.kds.fetch_vcek_der(processor_model, report)?;
                cert_map.insert("VCEK".to_string(), cert);
                if !vek_only {
                    let ca = self.kds.fetch_ca_der(processor_model, CertType::VCEK)?;
                    cert_map.insert("ARK".to_string(), ca[1].clone());
                    cert_map.insert("ASK".to_string(), ca[0].clone());
                }
                return Ok(cert_map);
            }
            let cert_map = self.cert_device.get_certificates_der()?;
            return Ok(cert_map);
        }
    }

    /// Verify the attestation report using the default settings.
    pub fn verify_attestation_report(&self, report: &AttestationReport) -> Result<()> {
        let signer_type = report.get_signer_type()?;
        if signer_type == CertType::VLEK {
            return self.common_attestation_flow(report, &signer_type, &AttestationFlow::Vlek);
        }
        self.common_attestation_flow(report, &signer_type, &AttestationFlow::Regular)
    }

    /// Verify the attestation report, but specify custom options for attestation flow.
    /// When in doubt, use the default `verify_attestation_report()` instead of this.
    pub fn verify_attestation_report_with_options(
        &self,
        report: &AttestationReport,
        flow: &AttestationFlow,
    ) -> Result<()> {
        let signer_type = report.get_signer_type()?;
        self.common_attestation_flow(report, &signer_type, flow)
    }

    /// Common base for all attestation verification
    fn common_attestation_flow(
        &self,
        report: &AttestationReport,
        signer_type: &CertType,
        flow: &AttestationFlow,
    ) -> Result<()> {
        let processor_model = cpu::get_processor_codename()?;

        if self.is_hyperv {
            // When running on HyperV, only the regular attestation workflow is supported.
            if flow != &AttestationFlow::Regular {
                return Err(SevSnpError::Firmware(
                    "Only Regular Attestation Flow is supported on Hyper-V!".to_string(),
                ));
            }
            self.regular_attestation_workflow(&report, processor_model)?;
        } else {
            // Device options does not matter when only retrieving certs from it.
            let device = device::Device::default(self.is_hyperv);
            let cert_map = device.get_certificates()?;
            match flow {
                AttestationFlow::Regular => {
                    if signer_type != &CertType::VCEK {
                        return Err(SevSnpError::Firmware(
                            "Regular attestation workflow can only be used if the report is signed with VCEK!".to_string(),
                        ));
                    }
                    self.regular_attestation_workflow(&report, processor_model)?;
                }
                AttestationFlow::Extended => {
                    if signer_type != &CertType::VCEK {
                        return Err(SevSnpError::Firmware(
                            "Extended attestation workflow can only be used if the report is signed with VCEK!".to_string(),
                        ));
                    }
                    if !(cert_map.contains_key("VCEK")
                        && cert_map.contains_key("ARK")
                        && cert_map.contains_key("ASK"))
                    {
                        return Err(SevSnpError::Firmware(
                            "Missing VCEK, ARK and ASK certs from host device to verify Attestation Report!".to_string())
                        );
                    }
                    self.extended_attestation_workflow(&report, &cert_map)?;
                }
                AttestationFlow::Vlek => {
                    if signer_type != &CertType::VLEK {
                        return Err(SevSnpError::Firmware(
                            "VLEK attestation workflow can only be used if the report is signed with VLEK!".to_string(),
                        ));
                    }
                    if !cert_map.contains_key("VLEK") {
                        return Err(SevSnpError::Firmware(
                            "Missing VLEK cert from host device to verify Attestation Report!"
                                .to_string(),
                        ));
                    }
                    self.vlek_attestation_workflow(&report, &cert_map, processor_model)?;
                }
            }
        }
        Ok(())
    }

    /// In the Extended Attestation workflow, all certificates used to verify the attestation report are
    /// fetched from the AMD SEV-SNP machine's hw device.
    /// This means that this workflow cannot be run outside an AMD SEV-SNP machine.
    fn extended_attestation_workflow(
        &self,
        report: &AttestationReport,
        cert_map: &HashMap<String, Certificate>,
    ) -> Result<()> {
        let cert_chain = CertificateChain::new(
            cert_map.get("ARK").unwrap().clone(),
            cert_map.get("ASK").unwrap().clone(),
            cert_map.get("VCEK").unwrap().clone(),
        );

        let verifier = verifier::Verifier::new(&cert_chain, &report);
        verifier.verify()
    }

    /// In the Regular Attestation workflow, all certificates used to verify the attestation report are
    /// fetched from the AMD Key Distribution Service (KDS).
    fn regular_attestation_workflow(
        &self,
        report: &AttestationReport,
        processor_model: &cpu::ProcType,
    ) -> Result<()> {
        let cert_chain = self.kds.fetch_vcek_cert_chain(processor_model, report)?;

        let verifier = verifier::Verifier::new(&cert_chain, &report);
        verifier.verify()
    }

    /// If only the VLEK certificate is available from the AMD SEV-SNP machine's hw device,
    /// the CA (ARK and ASK) certificates need to be fetched from the AMD Key Distribution Service (KDS),
    /// before we can verify the attestation report.
    /// This workflow cannot be run outside an AMD SEV-SNP machine.
    fn vlek_attestation_workflow(
        &self,
        report: &AttestationReport,
        cert_map: &HashMap<String, Certificate>,
        processor_model: &cpu::ProcType,
    ) -> Result<()> {
        let cert_chain = self
            .kds
            .fetch_vlek_cert_chain(processor_model, cert_map.get("VLEK").unwrap())?;

        let verifier = verifier::Verifier::new(&cert_chain, &report);
        verifier.verify()
    }
}

#[cfg(feature = "clib")]
pub mod c {
    use crate::device::DeviceOptions;

    use super::SevSnp;
    use crate::utils::AttestationReportExt;
    use once_cell::sync::Lazy;
    use sev::firmware::guest::AttestationReport;
    use sev::firmware::host::CertType;
    use std::ptr::copy_nonoverlapping;
    use std::sync::Mutex;
    use std::mem::size_of;

    static ATTESTATION_REPORT: Lazy<Mutex<Vec<u8>>> = Lazy::new(|| Mutex::new(Vec::new()));
    static VEK_CERT: Lazy<Mutex<Vec<u8>>> = Lazy::new(|| Mutex::new(Vec::new()));
    const REPORT_LEN: usize = size_of::<AttestationReport>();

    /// Use this function to generate the attestation report on Rust.
    /// Returns the size of the report, which you can use to malloc a buffer of suitable size
    /// before you call get_attestation_report_raw().
    #[no_mangle]
    pub extern "C" fn generate_attestation_report() -> usize {
        let sev_snp = SevSnp::new();
        let report = sev_snp.get_attestation_report().unwrap();
        let bytes = bincode::serialize(&report).unwrap();
        let len = bytes.len();
        match ATTESTATION_REPORT.lock() {
            Ok(mut t) => {
                *t = bytes;
            }
            Err(e) => {
                panic!("Error: {:?}", e);
            }
        }
        len
    }

    /// Use this function to generate the attestation report with options.
    /// Returns the size of the report, which you can use to malloc a buffer of suitable size
    /// before you call get_attestation_report_raw().
    #[no_mangle]
    pub extern "C" fn generate_attestation_report_with_options(
        report_data: *mut u8,
        vmpl: u32,
    ) -> usize {
        let sev_snp = SevSnp::new();
        let mut rust_report_data: [u8; 64] = [0; 64];
        unsafe {
            copy_nonoverlapping(report_data, rust_report_data.as_mut_ptr(), 64);
        }
        let device_options = DeviceOptions {
            report_data: Some(rust_report_data),
            vmpl: Some(vmpl),
        };
        let report = sev_snp
            .get_attestation_report_with_options(device_options)
            .unwrap();
        let bytes = bincode::serialize(&report).unwrap();
        let len = bytes.len();
        match ATTESTATION_REPORT.lock() {
            Ok(mut t) => {
                *t = bytes;
            }
            Err(e) => {
                panic!("Error: {:?}", e);
            }
        }
        len
    }

    /// Ensure that generate_attestation_report() is called first to get the size of buf.
    /// Use this size to malloc enough space for the attestation report that will be transferred.
    #[no_mangle]
    pub extern "C" fn get_attestation_report_raw(buf: *mut u8) {
        let bytes = match ATTESTATION_REPORT.lock() {
            Ok(t) => t.clone(),
            Err(e) => {
                panic!("Error: {:?}", e);
            }
        };
        if bytes.len() == 0 {
            panic!("Error: No attestation report found! Please call generate_attestation_report() first.");
        }

        unsafe {
            copy_nonoverlapping(bytes.as_ptr(), buf, bytes.len());
        }
    }

    /// Use this function to generate the vek cert.
    /// Returns the size of the vek cert, which can be used to malloc a buffer of suitable size
    #[no_mangle]
    pub extern "C" fn generate_vek_cert(c_report: *mut u8) -> usize {
        let sev_snp = SevSnp::new();
        let report_raw = unsafe { std::slice::from_raw_parts(c_report, REPORT_LEN) };
        let report: AttestationReport = bincode::deserialize_from(report_raw).unwrap();
        let signer_type = report.get_signer_type().unwrap();
        let flow = if signer_type == CertType::VLEK {
            &crate::AttestationFlow::Vlek
        } else {
            &crate::AttestationFlow::Regular
        };
        let cert_map = sev_snp.get_certificates(&report, flow, true).unwrap();
        let vek_cert = if cert_map.contains_key("VLEK") {
            cert_map.get("VLEK").unwrap()
        } else {
            cert_map.get("VCEK").unwrap()
        };
        let len = vek_cert.len();
        match VEK_CERT.lock() {
            Ok(mut t) => {
                *t = vek_cert.to_vec();
            }
            Err(e) => {
                panic!("Error: {:?}", e);
            }
        }
        len
    }

    /// Ensure that generate_vek_cert() is called first to get the size of buf.
    /// Use this size to malloc enough space for the vek cert that will be transferred.
    #[no_mangle]
    pub extern "C" fn get_vek_cert(buf: *mut u8) {
        let bytes = match VEK_CERT.lock() {
            Ok(t) => t.clone(),
            Err(e) => {
                panic!("Error: {:?}", e);
            }
        };
        if bytes.len() == 0 {
            panic!("Error: No VEK cert found! Please call generate_vek_cert() first.");
        }

        unsafe {
            copy_nonoverlapping(bytes.as_ptr(), buf, bytes.len());
        }
    }
}
