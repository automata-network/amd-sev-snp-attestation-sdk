//! Utility modules for CLI argument parsing and configuration.
//!
//! This module contains shared argument structures and helper functions
//! used across different CLI commands for configuring provers and smart contracts.

use alloy_primitives::Address;
use amd_sev_snp_attestation_prover::{AmdSevSnpProver, ProverConfig, SnpVerifierContract};
use anyhow::{anyhow, bail};
use clap::Args;

/// Command-line arguments for configuring zero-knowledge proof system settings.
///
/// Supports both RISC0 and SP1 proof systems with their respective configuration options.
/// Only one prover type should be specified at a time.
#[derive(Args, Clone)]
pub struct ProverArgs {
    #[cfg(feature = "risc0")]
    /// Use the RISC0 zkVM for proof generation
    #[arg(long)]
    pub risc0: bool,

    #[cfg(feature = "sp1")]
    /// Use the SP1 zkVM for proof generation
    #[arg(long)]
    pub sp1: bool,

    #[cfg(feature = "pico")]
    /// Use the Pico zkVM for proof generation
    #[arg(long)]
    pub pico: bool,

    /// Enable development mode for mock proof generation
    #[arg(long, default_value = "false", env = "DEV_MODE")]
    pub dev: bool,

    /// Private key for SP1 network prover
    #[arg(long, env = "SP1_PRIVATE_KEY")]
    pub sp1_private_key: Option<String>,

    /// RPC URL for SP1 network connection
    #[arg(long, env = "SP1_RPC_URL")]
    pub sp1_rpc_url: Option<String>,

    /// RPC URL for Boundless prover network
    #[arg(long, env = "BOUNDLESS_RPC_URL")]
    pub boundless_rpc_url: Option<String>,

    /// Private key for Boundless prover network (hex-encoded)
    #[arg(long, env = "BOUNDLESS_PRIVATE_KEY")]
    pub boundless_private_key: Option<String>,
}

impl ProverArgs {
    /// Creates a prover configuration based on the specified arguments.
    pub fn prover_config(&self) -> anyhow::Result<ProverConfig> {
        // Check for mutually exclusive flags
        let mut count = 0;
        #[cfg(feature = "sp1")]
        if self.sp1 { count += 1; }
        #[cfg(feature = "risc0")]
        if self.risc0 { count += 1; }
        #[cfg(feature = "pico")]
        if self.pico { count += 1; }

        if count > 1 {
            return Err(anyhow!(
                "Cannot use multiple zkVM options at the same time. Choose one: --sp1, --risc0, or --pico"
            ));
        }

        #[cfg(feature = "sp1")]
        if self.sp1 {
            use amd_sev_snp_attestation_prover::SP1ProverConfig;
            if let Some(sp1_private_key) = self.sp1_private_key.as_ref() {
                std::env::set_var("NETWORK_PRIVATE_KEY", sp1_private_key);
            }
            if let Some(sp1_rpc_url) = self.sp1_rpc_url.as_ref() {
                std::env::set_var("NETWORK_RPC_URL", sp1_rpc_url);
            }
            return Ok(ProverConfig::sp1_with(SP1ProverConfig {
                private_key: self.sp1_private_key.clone(),
                rpc_url: self.sp1_rpc_url.clone(),
            }));
        }

        #[cfg(feature = "risc0")]
        if self.risc0 {
            use amd_sev_snp_attestation_prover::RiscZeroProverConfig;
            return Ok(ProverConfig::risc0_with(RiscZeroProverConfig {
                rpc_url: self.boundless_rpc_url.clone(),
                private_key: self.boundless_private_key.clone(),
                ..Default::default()
            }));
        }

        #[cfg(feature = "pico")]
        if self.pico {
            use amd_sev_snp_attestation_prover::PicoProverConfig;
            return Ok(ProverConfig::pico_with(PicoProverConfig::default()));
        }

        bail!("No prover specified. Use --risc0, --sp1, or --pico to select a proof system.");
    }

    /// Creates a new `NitroEnclaveProver` instance with the configured settings.
    pub fn new_prover(
        &self,
        contract: Option<SnpVerifierContract>,
    ) -> anyhow::Result<AmdSevSnpProver> {
        Ok(AmdSevSnpProver::new(self.prover_config()?, contract))
    }
}

/// Command-line arguments for configuring smart contract interaction.
///
/// Used for on-chain proof verification and other blockchain operations.
#[derive(Args, Clone)]
pub struct ContractArgs {
    /// The address of the Nitro Enclave Verifier contract
    #[arg(long, env = "CONTRACT")]
    pub contract: Option<Address>,

    /// The RPC URL to connect to the Ethereum network
    #[arg(long, env = "RPC_URL", default_value = "http://localhost:8545")]
    pub rpc_url: Option<String>,

    #[arg(long, env = "PRIVATE_KEY")]
    pub private_key: Option<String>,
}

impl ContractArgs {
    /// Checks if the contract configuration is incomplete.
    pub fn empty(&self) -> bool {
        self.contract.is_none() || self.rpc_url.is_none()
    }

    /// Creates a contract interface if all required parameters are provided.
    pub fn stub(&self) -> anyhow::Result<Option<SnpVerifierContract>> {
        if self.empty() {
            return Ok(None);
        }
        let contract = *self.contract.as_ref().unwrap();
        let rpc_url = self.rpc_url.as_ref().unwrap();
        let verifier = SnpVerifierContract::dial(
            &rpc_url,
            contract,
            self.private_key.as_ref().map(|n| n.as_str()),
        )?;
        Ok(Some(verifier))
    }
}
