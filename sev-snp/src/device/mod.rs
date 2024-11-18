pub mod hyperv;
pub mod kvm;

use crate::error::Result;
use sev::certs::snp::Certificate;
use sev::firmware::guest::AttestationReport;
use std::collections::HashMap;

pub struct DeviceOptions {
    /// 64 bytes of user-defined data to use for the request.
    /// Only applicable for KVM. For HyperV, the the platform provides the data.
    /// Defaults to randomly generating 64 bytes.
    pub report_data: Option<[u8; 64]>,
    /// VMPL level that the Guest is running on. It is a number between 0 to 3.
    /// Defaults to 0 for kvm and 0 for Hyper-V.
    pub vmpl: Option<u32>,
}

/// Functions related to retrieving SEV-SNP data from a hardware device will go in here.
pub struct Device {
    options: DeviceOptions,
    is_hyperv: bool,
}

impl Device {
    /// Initialise SEV device with default options
    pub fn default(is_hyperv: bool) -> Self {
        let options = DeviceOptions {
            report_data: None,
            vmpl: None,
        };

        Device { options, is_hyperv }
    }

    /// Initialise SEV device with custom options
    pub fn new(options: DeviceOptions, is_hyperv: bool) -> Self {
        Device { options, is_hyperv }
    }

    /// Retrieve attestion report from SEV device.
    pub fn get_attestation_report(&self) -> Result<AttestationReport> {
        let report_data = match self.is_hyperv {
            true => {
                if self.options.report_data != None {
                    return Err(crate::error::SevSnpError::Firmware(
                        "User-defined report data is not supported on Azure."
                            .to_string(),
                    ));
                } else {
                    None
                }
            }
            false => self
                .options
                .report_data
                .or_else(crate::utils::generate_random_data),
        };

        let report = match self.is_hyperv {
            true => hyperv::get_attestation_report(report_data, self.options.vmpl.or(Some(0))),
            false => kvm::get_attestation_report(report_data, self.options.vmpl.or(Some(0))),
        }?;

        Ok(report)
    }

    /// Retrieve certificates from SEV device.
    pub fn get_certificates(&self) -> Result<HashMap<String, Certificate>> {
        match self.is_hyperv {
            true => Err(crate::error::SevSnpError::Firmware(
                "HyperV does not support fetching certificates".to_string(),
            )),
            false => kvm::get_certificates(),
        }
    }

    /// Retrieve certificates from SEV device.
    pub fn get_certificates_der(&self) -> Result<HashMap<String, Vec<u8>>> {
        match self.is_hyperv {
            true => Err(crate::error::SevSnpError::Firmware(
                "HyperV does not support fetching certificates".to_string(),
            )),
            false => kvm::get_certificates_der(),
        }
    }
}
