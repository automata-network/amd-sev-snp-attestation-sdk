use std::{
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use amd_sev_snp_attestation_prover::utils::AttestationReportWithVekCertChain;
use amd_sev_snp_attestation_verifier::stub::VerifierJournal;
use clap::{Args, Subcommand};

use crate::utils::{BackendSubcommand, ContractArgs};

#[cfg(feature = "sp1")]
#[derive(Args, Clone)]
pub struct ProveSp1Args {
    #[clap(flatten)]
    pub backend: crate::utils::Sp1Args,
    #[arg(long)]
    pub report: PathBuf,
    #[arg(long)]
    pub out: Option<PathBuf>,
    #[clap(flatten)]
    pub contract: ContractArgs,
    #[clap(long)]
    pub submit_on_chain: bool,
}

#[cfg(feature = "risc0")]
#[derive(Args, Clone)]
pub struct ProveRisc0Args {
    #[clap(flatten)]
    pub backend: crate::utils::Risc0Args,
    #[arg(long)]
    pub report: PathBuf,
    #[arg(long)]
    pub out: Option<PathBuf>,
    #[clap(flatten)]
    pub contract: ContractArgs,
    #[clap(long)]
    pub submit_on_chain: bool,
}

#[cfg(feature = "pico")]
#[derive(Args, Clone)]
pub struct ProvePicoArgs {
    #[clap(flatten)]
    pub backend: crate::utils::PicoArgs,
    #[arg(long)]
    pub report: PathBuf,
    #[arg(long)]
    pub out: Option<PathBuf>,
    #[clap(flatten)]
    pub contract: ContractArgs,
    #[clap(long)]
    pub submit_on_chain: bool,
}

#[derive(Subcommand, Clone)]
pub enum ProveBackend {
    /// Use the SP1 zkVM for proof generation.
    #[cfg(feature = "sp1")]
    Sp1(ProveSp1Args),
    /// Use the RISC0 zkVM for proof generation.
    #[cfg(feature = "risc0")]
    Risc0(ProveRisc0Args),
    /// Use the Pico zkVM for proof generation.
    #[cfg(feature = "pico")]
    Pico(ProvePicoArgs),
}

impl ProveBackend {
    fn as_backend(&self) -> BackendSubcommand {
        match self {
            #[cfg(feature = "sp1")]
            Self::Sp1(a) => BackendSubcommand::Sp1(a.backend.clone()),
            #[cfg(feature = "risc0")]
            Self::Risc0(a) => BackendSubcommand::Risc0(a.backend.clone()),
            #[cfg(feature = "pico")]
            Self::Pico(a) => BackendSubcommand::Pico(a.backend.clone()),
        }
    }

    fn report(&self) -> &PathBuf {
        match self {
            #[cfg(feature = "sp1")]
            Self::Sp1(a) => &a.report,
            #[cfg(feature = "risc0")]
            Self::Risc0(a) => &a.report,
            #[cfg(feature = "pico")]
            Self::Pico(a) => &a.report,
        }
    }

    fn out(&self) -> Option<&PathBuf> {
        match self {
            #[cfg(feature = "sp1")]
            Self::Sp1(a) => a.out.as_ref(),
            #[cfg(feature = "risc0")]
            Self::Risc0(a) => a.out.as_ref(),
            #[cfg(feature = "pico")]
            Self::Pico(a) => a.out.as_ref(),
        }
    }

    fn contract(&self) -> &ContractArgs {
        match self {
            #[cfg(feature = "sp1")]
            Self::Sp1(a) => &a.contract,
            #[cfg(feature = "risc0")]
            Self::Risc0(a) => &a.contract,
            #[cfg(feature = "pico")]
            Self::Pico(a) => &a.contract,
        }
    }

    fn submit_on_chain(&self) -> bool {
        match self {
            #[cfg(feature = "sp1")]
            Self::Sp1(a) => a.submit_on_chain,
            #[cfg(feature = "risc0")]
            Self::Risc0(a) => a.submit_on_chain,
            #[cfg(feature = "pico")]
            Self::Pico(a) => a.submit_on_chain,
        }
    }
}

#[derive(Args)]
pub struct ProveCli {
    /// Zero-knowledge proof backend.
    #[command(subcommand)]
    backend: ProveBackend,
}

impl ProveCli {
    pub fn run(&self) -> anyhow::Result<()> {
        let backend = self.backend.as_backend();

        let report_with_cert_chain =
            AttestationReportWithVekCertChain::decode(&std::fs::read(self.backend.report())?)?;

        let contract = self.backend.contract().stub()?;
        let prover = backend.new_prover(contract)?;

        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

        let result = prover.prove_attestation_report(
            timestamp,
            report_with_cert_chain.report,
            report_with_cert_chain.vek_certs,
        )?;

        let output = VerifierJournal::decode(&result.raw_proof.journal)?;

        if let Some(out) = self.backend.out() {
            std::fs::write(out, result.encode_json()?)?;
        }

        println!("proof: {:?}", result);
        println!("journal: {:?}", output);

        if self.backend.submit_on_chain() {
            let receipt = prover.submit_on_chain(&result)?;
            println!("receipt: {:?}", receipt);
        }

        Ok(())
    }
}
