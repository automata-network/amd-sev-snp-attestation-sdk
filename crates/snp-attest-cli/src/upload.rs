//! Program upload functionality for remote zero-knowledge proof generation.
//!
//! This module handles uploading ZK program images to remote proving services
//! (SP1 and RISC0), allowing for distributed proof generation.

use std::path::PathBuf;

use amd_sev_snp_attestation_prover::set_prover_dev_mode;
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
    pub fn run(&self) -> anyhow::Result<()> {
        // Force network prover for uploads (dev mode programs cannot be uploaded)
        set_prover_dev_mode(false);
        
        // Create prover without contract binding (uploads don't need contracts)
        let prover = self.prover.new_prover(None)?;
        let result = prover.upload_program_images()?;

        // Save program ID to file if output path is specified
        if let Some(out) = &self.out {
            std::fs::write(out, result.encode_json(prover.get_zk_type())?)?;
        }

        // Display program information to stdout
        dbg!(result);
        Ok(())
    }
}
