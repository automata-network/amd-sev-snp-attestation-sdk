//! Program upload functionality for remote zero-knowledge proof generation.
//!
//! This module handles uploading ZK program images to remote proving services
//! (SP1 and RISC0), allowing for distributed proof generation.

use std::path::PathBuf;

use atakit_zk_prover::Program;
use clap::Args;

use crate::utils::ProverArgs;

/// Command-line arguments for uploading ZK programs to remote proving services.
///
/// This enables distributed proof generation by uploading the necessary program
/// images to SP1 or RISC0 remote proving infrastructure.
#[derive(Args)]
pub struct UploadCli {
    #[clap(flatten)]
    prover: ProverArgs,

    /// Output file path for storing the program identifier
    ///
    /// The program ID is needed for setup the NitroEnclaveVerifierContract.
    /// If not specified, the program ID will only be displayed to stdout.
    #[clap(long)]
    out: Option<PathBuf>,
}

impl UploadCli {
    /// Executes the program upload command.
    ///
    /// This method:
    /// 1. Disables development mode (uploads require production builds)
    /// 2. Creates a prover instance without contract binding
    /// 3. Uploads the ZK program images to the remote service
    /// 4. Saves the program ID for future use
    pub async fn run(&self) -> anyhow::Result<()> {
        // Create prover without contract binding (uploads don't need contracts)
        let prover = self.prover.new_prover()?;
        let program = Program::new::<program_verifier::Guest>()?;
        let remote_variant = prover.upload_program(&program).await?;
        let output = serde_json::to_string_pretty(&remote_variant)?;

        if let Some(out) = &self.out {
            println!("{output}");
            std::fs::write(out, output)?;
        } else {
            println!("{output}");
        }

        Ok(())
    }
}
