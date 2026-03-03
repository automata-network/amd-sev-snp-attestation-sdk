use std::path::PathBuf;

use clap::{Args, Subcommand};

use crate::utils::BackendSubcommand;

#[cfg(feature = "sp1")]
#[derive(Args, Clone)]
pub struct UploadSp1Args {
    #[clap(flatten)]
    pub backend: crate::utils::Sp1Args,
    /// Output file path for storing the program identifier.
    #[clap(long)]
    pub out: Option<PathBuf>,
}

#[cfg(feature = "risc0")]
#[derive(Args, Clone)]
pub struct UploadRisc0Args {
    #[clap(flatten)]
    pub backend: crate::utils::Risc0Args,
    /// Output file path for storing the program identifier.
    #[clap(long)]
    pub out: Option<PathBuf>,
}

#[cfg(feature = "pico")]
#[derive(Args, Clone)]
pub struct UploadPicoArgs {
    #[clap(flatten)]
    pub backend: crate::utils::PicoArgs,
    /// Output file path for storing the program identifier.
    #[clap(long)]
    pub out: Option<PathBuf>,
}

#[derive(Subcommand, Clone)]
pub enum UploadBackend {
    /// Use the SP1 zkVM.
    #[cfg(feature = "sp1")]
    Sp1(UploadSp1Args),
    /// Use the RISC0 zkVM.
    #[cfg(feature = "risc0")]
    Risc0(UploadRisc0Args),
    /// Use the Pico zkVM.
    #[cfg(feature = "pico")]
    Pico(UploadPicoArgs),
}

impl UploadBackend {
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
}

#[derive(Args)]
pub struct UploadCli {
    /// Zero-knowledge proof backend.
    #[command(subcommand)]
    backend: UploadBackend,
}

impl UploadCli {
    pub fn run(&self) -> anyhow::Result<()> {
        let backend = self.backend.as_backend();

        let prover = backend.new_prover(None)?;
        let result = prover.upload_program_images()?;

        if let Some(out) = self.backend.out() {
            std::fs::write(out, result.encode_json(prover.get_zk_type())?)?;
        }

        dbg!(result);
        Ok(())
    }
}
