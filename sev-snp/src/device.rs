use crate::error::Result;
use crate::utils::generate_random_data;
use crate::utils::CertTypeExt;
use crate::SevSnpError;
#[cfg(feature = "configfs")]
use coco_provider::coco::configfs::ConfigFs;
#[cfg(feature = "legacy")]
use coco_provider::coco::legacy::Legacy;
use sev::certs::snp::Certificate;
use sev::firmware::guest::AttestationReport;
use sev::firmware::host::CertTableEntry;
use std::collections::HashMap;

use coco_provider::{
    coco::{CocoDeviceType, ReportRequest},
    get_coco_provider, CocoProvider,
};

/// This struct is used to specify the options for generating the attestation report.
pub struct ReportOptions {
    /// 64 bytes of user-defined data to use for the request.
    /// Only applicable when the device is configfs or legacy.
    /// If the device is a TPM, the report_data will be provided by the device instead.
    /// Defaults to randomly generating 64 bytes.
    pub report_data: Option<[u8; 64]>,
    /// VMPL level that the Guest is running on. It is a number between 0 to 3.
    /// Defaults to 0 for kvm and 0 for Hyper-V.
    /// 0 represents the highest privilege level and 3 represents the lowest.
    /// If unsure of what VMPL to pick, use 0.
    pub vmpl: Option<u32>,
}

impl ReportOptions {
    pub fn default() -> Self {
        ReportOptions {
            report_data: None,
            vmpl: None,
        }
    }
}

pub enum RootKeyType {
    VCEK,
    VMRK,
}

/// This struct is used to specify the options for retrieving a derived key.
/// Note that ConfigFS does not support generating a derived key.
/// So, it can only be done using a legacy /dev/sev-guest device.
pub struct DerivedKeyOptions {
    /// Pick a root key from which to derive the derived key.
    /// Defaults to VECK
    pub root_key_type: Option<RootKeyType>,
    /// Specify which Guest Field Select bits to enable. It is a 6 digit binary string. For each bit, 0 denotes off and 1 denotes on.
    /// The least significant (rightmost) bit is Guest Policy followed by Image ID, Family ID, Measurement, SVN, TCB Version which is the most significant (leftmost) bit.
    /// Example: "000000" means all bits are off.
    /// Example: "100001" means only the Guest Policy and TCB Version bits are on.
    /// Defaults to None (or 0)
    pub guest_field_sel: Option<String>,
    /// Specify the guest SVN to mix into the key. Must not exceed the guest SVN provided at launch in the ID block.
    /// Defaults to None (or 0)
    pub guest_svn: Option<u32>,
    /// Specify the TCB version to mix into the derived key. Must not exceed CommittedTcb.
    /// Defaults to None (or 0)
    pub tcb_version: Option<u64>,
    /// VMPL level that the Guest is running on. It is a number between 0 to 3.
    /// Defaults to 0.
    pub vmpl: Option<u32>,
}

impl DerivedKeyOptions {
    pub fn default() -> Self {
        DerivedKeyOptions {
            root_key_type: Some(RootKeyType::VCEK),
            guest_field_sel: None,
            guest_svn: None,
            tcb_version: None,
            vmpl: Some(0),
        }
    }
}

/// Functions related to retrieving SEV-SNP data from a hardware device will go in here.
pub struct Device {
    provider: CocoProvider,
}

impl Device {
    /// Initialise SEV device with custom options
    pub fn new() -> Result<Self> {
        let provider = get_coco_provider()?;
        if provider.device_type == CocoDeviceType::Mock {
            return Err(SevSnpError::ConfigOptions(
                "Mock device is not supported!".to_string(),
            ));
        }
        Ok(Device { provider })
    }

    /// Retrieve attestion report from SEV device.
    pub fn get_attestation_report(
        &self,
        options: &ReportOptions,
    ) -> Result<(AttestationReport, Option<Vec<u8>>)> {
        let (raw_report, var_data) = self.get_attestation_report_raw(options)?;
        let report: AttestationReport = bincode::deserialize(&raw_report)?;
        Ok((report, var_data))
    }

    pub fn get_attestation_report_raw(
        &self,
        options: &ReportOptions,
    ) -> Result<(Vec<u8>, Option<Vec<u8>>)> {
        let report_data = match self.provider.device_type {
            CocoDeviceType::Tpm => {
                if !options.report_data.is_none() {
                    return Err("report_data cannot be provided for TPM!".into());
                }
                None
            }
            _ => options.report_data.or_else(generate_random_data),
        };
        let vmpl = match self.provider.device_type {
            CocoDeviceType::Tpm => {
                if !options.vmpl.is_none() {
                    return Err("vmpl cannot be provided for TPM!".into());
                }
                None
            }
            _ => options.vmpl.or(Some(0)),
        };
        let req = ReportRequest { report_data, vmpl };
        let report = self.provider.device.get_report(&req)?;
        Ok((report.report, report.var_data))
    }

    /// Get certificates (as Certificate objects) via /dev/sev-guest device
    /// The output mapping should at least contain 3 entries (ARK, ASK and VCEK)
    /// or at least 1 entry (VLEK).
    pub fn get_certificates(&self) -> Result<HashMap<String, Certificate>> {
        if self.provider.device_type == CocoDeviceType::Tpm {
            return Err(crate::error::SevSnpError::Firmware(
                "HyperV does not support fetching certificates".to_string(),
            ));
        }

        let raw_certs = self.get_certificates_raw()?;
        let mut cert_map: HashMap<String, Certificate> = HashMap::new();

        for certificate in raw_certs {
            let cert_data = certificate.data();
            let cert = Certificate::from_bytes(cert_data)?;
            cert_map.insert(certificate.cert_type.string(), cert);
        }

        Ok(cert_map)
    }

    /// Get certificates (as raw DER).
    /// The output mapping should at least contain 3 entries (ARK, ASK and VCEK)
    /// or at least 1 entry (VLEK).
    pub fn get_certificates_der(&self) -> Result<HashMap<String, Vec<u8>>> {
        if self.provider.device_type == CocoDeviceType::Tpm {
            return Err(SevSnpError::Firmware(
                "HyperV does not support fetching certificates".to_string(),
            ));
        }

        let raw_certs = self.get_certificates_raw()?;
        let mut cert_map: HashMap<String, Vec<u8>> = HashMap::new();

        for certificate in raw_certs {
            let cert_data = certificate.data();
            cert_map.insert(certificate.cert_type.string(), Vec::<u8>::from(cert_data));
        }

        Ok(cert_map)
    }

    /// Generate the Derived Key
    pub fn get_derived_key(&self, _options: &DerivedKeyOptions) -> Result<[u8; 32]> {
        #[cfg(feature = "legacy")]
        {
            if self.provider.legacy_device.is_some() {
                let dev = self.provider.legacy_device.unwrap();

                let root_key_sel = match _options
                    .root_key_type
                    .as_ref()
                    .unwrap_or(&RootKeyType::VCEK)
                {
                    RootKeyType::VCEK => false,
                    RootKeyType::VMRK => true,
                };
                let vmpl = _options.vmpl.unwrap_or(0);
                let guest_field_sel: u64 = match _options.guest_field_sel.as_ref() {
                    Some(val) => u64::from_str_radix(&val, 2).unwrap(),
                    None => 0,
                };
                let guest_svn = _options.guest_svn.unwrap_or(0);
                let tcb_version = _options.tcb_version.unwrap_or(0);

                self.verify_key_options(vmpl, guest_field_sel)?;

                return Ok(dev.get_derived_key(
                    root_key_sel,
                    vmpl,
                    guest_field_sel,
                    guest_svn,
                    tcb_version,
                )?);
            }
        }
        Err(SevSnpError::Firmware(format!(
            "Retrieving derived key from Device Type {:?} is not supported!",
            self.provider.device_type
        )))
    }

    pub fn get_device_type(&self) -> CocoDeviceType {
        self.provider.device_type
    }

    #[cfg(feature = "legacy")]
    fn verify_key_options(&self, vmpl: u32, guest_field_sel: u64) -> Result<()> {
        if vmpl > 3 {
            return Err(SevSnpError::ConfigOptions(format!(
                "Invalid VMPL {}: Should be a number between 0 - 3",
                vmpl
            )));
        }
        if guest_field_sel > 63 {
            return Err(SevSnpError::ConfigOptions(format!(
                "Invalid guest_field_sel {}: Should be a number less than 64",
                guest_field_sel
            )));
        }
        Ok(())
    }

    fn get_certificates_raw(&self) -> Result<Vec<CertTableEntry>> {
        if self.provider.device_type == CocoDeviceType::Legacy {
            #[cfg(feature = "legacy")]
            {
                let dev = self
                    .provider
                    .device
                    .as_any()
                    .downcast_ref::<Legacy>()
                    .unwrap();

                return Ok(dev.get_certificates()?);
            }
        } else if self.provider.device_type == CocoDeviceType::ConfigFs {
            #[cfg(feature = "configfs")]
            {
                let dev = self
                    .provider
                    .device
                    .as_any()
                    .downcast_ref::<ConfigFs>()
                    .unwrap();
                let mut certs_bytes = dev.get_certificates()?;
                // certs from configfs auxblob follows the SEV specification in Section 4.1.8.1 MSG_REPORT_REQ
                // ref: https://www.kernel.org/doc/Documentation/ABI/testing/configfs-tsm
                let certs = CertTableEntry::vec_bytes_to_cert_table(certs_bytes.as_mut_slice())?;
                return Ok(certs);
            }
        }
        Err(SevSnpError::Firmware(format!(
            "Unable to get certs from Device Type {:?}. \
            Please ensure legacy or configfs feature is enabled and the device type is correct.",
            self.provider.device_type
        )))
    }
}
