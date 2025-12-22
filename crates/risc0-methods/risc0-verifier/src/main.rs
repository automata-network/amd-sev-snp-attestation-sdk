use std::io::Read;

use amd_sev_snp_attestation_verifier::{stub::VerifierInput, verify_attestation};
use risc0_zkvm::guest::env;

fn main() -> anyhow::Result<()> {
    // Read the input
    let mut input_bytes = Vec::<u8>::new();
    env::stdin().read_to_end(&mut input_bytes)?;
    let input = VerifierInput::decode(&input_bytes)?;
    let output = verify_attestation(input)?;
    env::commit_slice(&output.encode());
    Ok(())
}
