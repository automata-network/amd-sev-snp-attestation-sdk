use std::{
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use amd_sev_snp_attestation_prover::{set_prover_dev_mode, utils::AttestationReportWithVekCertChain};
use amd_sev_snp_attestation_verifier::stub::VerifierJournal;
use clap::Args;

use crate::utils::{ContractArgs, ProverArgs};

/// Command-line arguments for the prove subcommand.
///
/// Generates zero-knowledge proofs from one or more AMD SEV-SNP attestation reports.
/// Supports both single report verification and multi-report aggregation.
#[derive(Args)]
pub struct ProveCli {
    /// Path to AMD SEV-SNP attestation report files
    ///
    /// Can specify multiple report files to generate an aggregated proof.
    /// Each file should contain a binary attestation report from AMD SEV-SNP.
    #[arg(long)]
    report: PathBuf,

    /// Output file path for the generated proof
    ///
    /// If not specified, the proof will only be printed to stdout.
    /// The output format is JSON containing the proof data and metadata.
    #[arg(long)]
    out: Option<PathBuf>,

    /// Zero-knowledge proof system configuration
    #[clap(flatten)]
    prover: ProverArgs,

    /// Smart contract configuration for on-chain verification
    #[clap(flatten)]
    contract: ContractArgs,

    #[clap(long)]
    submit_on_chain: bool,
}

impl ProveCli {
    /// Executes the proof generation command.
    ///
    /// This method orchestrates the entire proof generation process:
    /// 1. Configures the prover with development mode settings
    /// 2. Validates input parameters
    /// 3. Reads attestation report files
    /// 4. Creates the appropriate prover instance
    /// 5. Generates proofs (single or aggregated)
    /// 6. Outputs results to file and/or stdout
    pub fn run(&self) -> anyhow::Result<()> {
        set_prover_dev_mode(self.prover.dev);

        let report_with_cert_chain =
            AttestationReportWithVekCertChain::decode(&std::fs::read(&self.report)?)?;

        // Initialize smart contract interface (if configured)
        let contract = self.contract.stub()?;

        // Create the prover instance with the specified configuration
        let prover = self.prover.new_prover(contract)?;

        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

        // Generate proof based on the number of input reports
        let result = prover.prove_attestation_report(
            timestamp,
            report_with_cert_chain.report,
            report_with_cert_chain.vek_certs,
        )?;

        let output: VerifierJournal = result.raw_proof.decode_journal()?;

        // Write proof to output file if specified
        if let Some(out) = &self.out {
            std::fs::write(out, result.encode_json()?)?;
        }

        // Display proof information to stdout
        println!("proof: {:?}", result);
        println!("journal: {:?}", output);

        if self.submit_on_chain {
            let receipt = prover.submit_on_chain(&result)?;
            println!("receipt: {:?}", receipt);
        }

        Ok(())
    }
}
