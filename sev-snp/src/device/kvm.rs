use std::collections::HashMap;

use crate::error::{Result, SevSnpError};
use crate::utils::CertTypeExt;
use sev::certs::snp::Certificate;
use sev::firmware::guest::{AttestationReport, Firmware};
use sev::firmware::host::CertTableEntry;

/// Get attestation report via /dev/sev-guest device
pub fn get_attestation_report(
    data: Option<[u8; 64]>,
    vmpl: Option<u32>,
) -> Result<AttestationReport> {
    // Try to open /dev/sev-guest
    let mut fw = Firmware::open()?;
    // Get attestation report
    Ok(fw.get_report(None, data, vmpl)?)
}

/// Get certificates (as Certificate objects) via /dev/sev-guest device
/// The output mapping should at least contain 3 entries (ARK, ASK and VCEK)
/// or at least 1 entry (VLEK).
pub fn get_certificates() -> Result<HashMap<String, Certificate>> {
    let raw_certs = get_certificates_raw()?;
    let mut cert_map: HashMap<String, Certificate> = HashMap::new();

    for certificate in raw_certs {
        let cert_data = certificate.data();
        let cert = Certificate::from_bytes(cert_data)?;
        cert_map.insert(certificate.cert_type.string(), cert);
    }

    Ok(cert_map)
}

/// Get certificates (as raw DER) via /dev/sev-guest device
/// The output mapping should at least contain 3 entries (ARK, ASK and VCEK)
/// or at least 1 entry (VLEK).
pub fn get_certificates_der() -> Result<HashMap<String, Vec<u8>>> {
    let raw_certs = get_certificates_raw()?;
    let mut cert_map: HashMap<String, Vec<u8>> = HashMap::new();

    for certificate in raw_certs {
        let cert_data = certificate.data();
        cert_map.insert(certificate.cert_type.string(), Vec::<u8>::from(cert_data));
    }

    Ok(cert_map)
}

fn get_certificates_raw() -> Result<Vec<CertTableEntry>> {
    let mut fw: Firmware = Firmware::open()?;

    // Generate random request data
    let request_data: [u8; 64] = crate::utils::generate_random_data().unwrap();

    // Call get_ext_report, drop the attestation report and only care about the certs it returns.
    let (_, certificates) = fw.get_ext_report(None, Some(request_data), None)?;

    if certificates.is_some() {
        return Ok(certificates.unwrap());
    }

    Err(SevSnpError::Firmware(
        "No certificates were loaded by the host!".to_string(),
    ))
}
