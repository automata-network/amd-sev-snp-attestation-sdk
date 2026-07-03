mod debug;
mod program_id;
mod proof;
mod prove;
mod upload;
mod utils;

use clap::{Parser, Subcommand};
use tracing::level_filters::LevelFilter;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "snp-attest-cli")]
#[command(version)]
#[command(about = "CLI for AMD SEV-SNP attestation proof generation and verification")]
struct SnpAttestCli {
    #[command(subcommand)]
    command: Commands,
}

/// Available subcommands for the CLI
#[derive(Subcommand)]
enum Commands {
    /// Generate zero-knowledge proofs from AMD SEV-SNP attestation reports
    Prove(prove::ProveCli),

    /// Upload ZK programs for remote execution
    Upload(upload::UploadCli),

    #[clap(subcommand)]
    Debug(debug::DebugCli),

    #[clap(subcommand)]
    Proof(proof::ProofCli),

    /// Print the program ID of the zkVM program
    ProgramId(program_id::ProgramIdCli),
}

fn main() -> anyhow::Result<()> {
    // Load environment variables from .env file if present
    dotenvy::dotenv().ok();

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::INFO.into())
                .from_env_lossy(),
        )
        .init();

    let cli = SnpAttestCli::parse();
    match &cli.command {
        Commands::Prove(cli) => cli.run()?,
        Commands::Upload(cli) => cli.run()?,
        Commands::Debug(cli) => cli.run()?,
        Commands::Proof(cli) => cli.run()?,
        Commands::ProgramId(cli) => cli.run()?,
    }
    Ok(())
}
