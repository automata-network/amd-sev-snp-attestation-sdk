use crate::utils::ProverArgs;
use clap::Args;

#[derive(Args)]
pub struct ProgramIdCli {
    #[clap(flatten)]
    prover: ProverArgs,
}

impl ProgramIdCli {
    pub fn run(&self) -> anyhow::Result<()> {
        let prover = self.prover.new_prover(None)?;
        let program_id = prover.get_program_id();
        println!("ProgramID (Onchain Representation): {}", program_id.verifier_id);
        println!("ProgramID (Offchain Representation): {}", program_id.verify_proof_id);
        Ok(())
    }
}
