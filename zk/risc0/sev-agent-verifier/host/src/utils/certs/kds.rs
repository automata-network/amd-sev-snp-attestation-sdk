use anyhow::Result;

use sev_snp_lib::types::{CertType, ProcType};
use sev_snp_lib::attestation::AttestationReport;
use super::fetch_certificate;

const KDS_BASE_URL: &str = "https://kdsintf.amd.com/";

pub fn fetch_vek_issuer_ca_pem_chain(
    processor_model: &ProcType,
    cert_type: &CertType
) -> Result<Vec<u8>> {
    let kds_url = format!(
        "{}/{}/v1/{}/cert_chain", 
        KDS_BASE_URL,
        cert_type.to_str(),
        processor_model.to_str()
    );

    let res = fetch_certificate(kds_url.as_str())?;
    Ok(res)
}

pub fn fetch_vcek_pem (
    processor_model: &ProcType,
    report: &AttestationReport
) -> Result<Vec<u8>> {
    let reported_tcb = report.reported_tcb;
    let chip_id = hex::encode(report.chip_id.as_slice());
    let kds_url = format!(
        "{}/{}/v1/{}/{}?blSPL={:02}&teeSPL={:02}&snpSPL={:02}&ucodeSPL={:02}",
        KDS_BASE_URL,
        CertType::VCEK.to_str(),
        processor_model.to_str(),
        chip_id,
        reported_tcb.bootloader,
        reported_tcb.tee,
        reported_tcb.snp,
        reported_tcb.microcode
    );

    println!("{}", kds_url);

    let res = fetch_certificate(kds_url.as_str())?;
    Ok(res)
}