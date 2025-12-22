#![no_main]
sp1_zkvm::entrypoint!(main);

use amd_sev_snp_attestation_verifier::{stub::VerifierInput, verify_attestation};

pub fn main() {
    entrypoint().unwrap()
}

pub fn entrypoint() -> anyhow::Result<()> {
    let input = sp1_zkvm::io::read_vec();
    let output = verify_attestation(VerifierInput::decode(&input)?)?;
    sp1_zkvm::io::commit_slice(&output.encode());
    Ok(())
}
