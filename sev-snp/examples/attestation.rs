use base64::prelude::*;
use sev::firmware::host::CertType;
use sev_snp::utils::AttestationReportExt;
use sev_snp::AttestationFlow;
use sev_snp::SevSnp;

fn main() {
    // Initialise an SevSnp object
    let sev_snp = SevSnp::new();

    // Retrieve an attestation report with default options passed to the hardware device
    let report = sev_snp.get_attestation_report().unwrap();
    println!("Attestation Report: {:?}", report);

    // Verify the attestation report
    sev_snp.verify_attestation_report(&report).unwrap();
    println!("Verification successful!");

    let bytes = bincode::serialize(&report).unwrap();
    println!("Base64 encode report: {:?}", BASE64_STANDARD.encode(bytes));
    let signer_type = report.get_signer_type().unwrap();
    let flow = if signer_type == CertType::VLEK {
        &crate::AttestationFlow::Vlek
    } else {
        &crate::AttestationFlow::Regular
    };
    let cert_map = sev_snp.get_certificates(&report, flow, false).unwrap();
    let vek_cert = if cert_map.contains_key("VLEK") {
        cert_map.get("VLEK").unwrap()
    } else {
        cert_map.get("VCEK").unwrap()
    };
    println!(
        "Base64 encode vek_cert: {:?}",
        BASE64_STANDARD.encode(vek_cert)
    );
}
