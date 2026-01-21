use crate::utils::ProverArgs;
use clap::Args;
use alloy_primitives::B256;

#[derive(Args)]
pub struct ProgramIdCli {
    #[clap(flatten)]
    prover: ProverArgs,
}

impl ProgramIdCli {
    pub fn run(&self) -> anyhow::Result<()> {
        let prover = self.prover.new_prover(None)?;
        let program_id = prover.get_program_id();
        println!("ProgramID (Onchain): {}", program_id.verifier_id);

        // Convert LE words to BE for display
        let verify_proof_id_bytes = program_id.verify_proof_id.0;
        let be_words: [u32; 8] = unsafe { std::mem::transmute(verify_proof_id_bytes) };
        let be_converted: [u32; 8] = be_words.map(|word| word.to_be());
        let be_bytes: [u8; 32] = unsafe { std::mem::transmute(be_converted) };
        let be_b256 = B256::from(be_bytes);

        println!("ProgramID (Offchain): {}", be_b256);
        Ok(())
    }
}
