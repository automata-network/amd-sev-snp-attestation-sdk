use sev_snp::SevSnp;

fn main() {
    // Initialise an SevSnp object
    let sev_snp = SevSnp::new().unwrap();

    // Retrieve an attestation report with default options passed to the hardware device
    let (report, _) = sev_snp.get_attestation_report().unwrap();

    println!("Attestation Report: {}", report);

    // Verify the attestation report
    sev_snp.verify_attestation_report(&report, None).unwrap();

    println!("Verification successful!");
}
