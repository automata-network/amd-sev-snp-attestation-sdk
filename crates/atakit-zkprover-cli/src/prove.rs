use std::{
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use atakit_zk_prover::Program;
use clap::Args;
use contract_stub::ZkCoProcessorType;
use program_verifier::VerifierInput;

use crate::utils::{AttestationReportWithVekCertChain, ContractArgs, ProverArgs, VmArg};

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
    verify_on_chain: bool,
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
    pub async fn run(&self) -> anyhow::Result<()> {
        let report_with_cert_chain =
            AttestationReportWithVekCertChain::decode(&std::fs::read(&self.report)?)?;

        // Initialize smart contract interface (if configured)
        let contract = self.contract.stub()?;

        // Create the prover instance with the specified configuration
        let prover = self.prover.new_prover()?;

        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

        let mut vek_certs = report_with_cert_chain.vek_certs.unwrap_or_default();
        vek_certs.reverse();
        let input = VerifierInput {
            timestamp,
            rawReport: report_with_cert_chain.report,
            vekDerChain: vek_certs,
        };

        let program = Program::new::<program_verifier::Guest>()?;

        let result = prover
            .with_program(&program)
            .groth16()
            .prove(&input)
            .await?;

        let program_id = program
            .variant(prover.config().vm)
            .map(|n| n.program_id())
            .unwrap();

        // Display proof information to stdout

        dbg!(&result.output);
        println!("proof: {:?}", result.artifact.proof_bytes());
        println!("journal: {:?}", result.artifact.journal());
        println!("program_id: {:?}", program_id);

        let proof = result.artifact.proof_bytes()?;

        if self.verify_on_chain {
            if let Some(contract) = contract {
                let zk = match self.prover.vm {
                    VmArg::Risc0 => ZkCoProcessorType::RiscZero,
                    VmArg::Sp1 => ZkCoProcessorType::Succinct,
                };
                let journal = contract
                    .call_verify(zk, proof.bytes, result.artifact.journal())
                    .await?;
                dbg!(journal);
            }
        }

        Ok(())
    }
}
