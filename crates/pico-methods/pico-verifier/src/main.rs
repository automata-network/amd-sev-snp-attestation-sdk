#![no_main]
pico_sdk::entrypoint!(main);

use amd_sev_snp_attestation_verifier::{stub::VerifierInput, verify_attestation};

pub fn main() {
    entrypoint().unwrap()
}

pub fn entrypoint() -> anyhow::Result<()> {
    let input = pico_sdk::io::read_vec();
    let output = verify_attestation(VerifierInput::decode(&input)?)?;
    pico_sdk::io::commit_bytes(&output.encode());
    Ok(())
}
