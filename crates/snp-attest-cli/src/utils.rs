//! Utility modules for CLI argument parsing and configuration.
//!
//! This module contains shared argument structures and helper functions
//! used across different CLI commands for configuring provers and smart contracts.

use alloy_primitives::Address;
use amd_sev_snp_attestation_prover::{AmdSevSnpProver, ProverConfig, SnpVerifierContract};
use clap::{Args, Subcommand, ValueEnum};

/// Proof type for Boundless proving (CLI enum).
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Default)]
pub enum BoundlessProofTypeCli {
    #[default]
    #[value(name = "groth16")]
    Groth16,
    #[value(name = "merkle")]
    Merkle,
}

#[cfg(feature = "sp1")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Default)]
pub enum Sp1ProvingStrategyCli {
    #[value(name = "dev")]
    Dev,
    #[value(name = "local")]
    Local,
    #[default]
    #[value(name = "network")]
    Network,
}

#[cfg(feature = "risc0")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Default)]
pub enum Risc0ProvingStrategyCli {
    #[value(name = "dev")]
    Dev,
    #[value(name = "local")]
    Local,
    #[default]
    #[value(name = "boundless")]
    Boundless,
}

#[cfg(feature = "pico")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Default)]
pub enum PicoProvingStrategyCli {
    #[value(name = "dev")]
    Dev,
    #[value(name = "local")]
    Local,
    #[default]
    #[value(name = "marketplace")]
    Marketplace,
}

/// Shared arguments common to all prover backends.
#[derive(Args, Clone)]
pub struct SharedProverArgs {
    /// Enable development mode for mock proof generation (compatibility override).
    #[arg(long, default_value = "false", env = "DEV_MODE")]
    pub dev: bool,
}

/// SP1-specific prover arguments.
#[cfg(feature = "sp1")]
#[derive(Args, Clone)]
pub struct Sp1Args {
    #[clap(flatten)]
    pub shared: SharedProverArgs,

    /// SP1 proving strategy: dev, local, or network.
    #[arg(long = "strategy", value_enum, default_value = "network")]
    pub strategy: Sp1ProvingStrategyCli,

    /// Private key for SP1 network prover.
    #[arg(long = "sp1-private-key", env = "SP1_PRIVATE_KEY")]
    pub sp1_private_key: Option<String>,

    /// RPC URL for SP1 prover network.
    #[arg(long, env = "SP1_RPC_URL")]
    pub sp1_rpc_url: Option<String>,
}

/// RISC0-specific prover arguments.
#[cfg(feature = "risc0")]
#[derive(Args, Clone)]
pub struct Risc0Args {
    #[clap(flatten)]
    pub shared: SharedProverArgs,

    /// RISC0 proving strategy: dev, local, or boundless.
    #[arg(long = "strategy", value_enum, default_value = "boundless")]
    pub strategy: Risc0ProvingStrategyCli,

    /// Boundless RPC URL for RISC0 proving.
    #[arg(long, env = "BOUNDLESS_RPC_URL")]
    pub boundless_rpc_url: Option<String>,

    /// Boundless wallet private key (hex-encoded).
    #[arg(long = "boundless-private-key", env = "BOUNDLESS_PRIVATE_KEY")]
    pub boundless_private_key: Option<String>,

    /// Verifier program URL for pre-uploaded ELF (optional, uploads to IPFS if not set).
    #[arg(long, env = "BOUNDLESS_VERIFIER_PROGRAM_URL")]
    pub verifier_program_url: Option<String>,

    /// Proof type for Boundless proving (groth16 or merkle).
    #[arg(long, value_enum, default_value = "groth16")]
    pub proof_type: BoundlessProofTypeCli,

    /// Minimum price in wei per cycle.
    #[arg(long, env = "BOUNDLESS_MIN_PRICE")]
    pub min_price: Option<u128>,

    /// Maximum price in wei per cycle.
    #[arg(long, env = "BOUNDLESS_MAX_PRICE")]
    pub max_price: Option<u128>,

    /// Timeout in seconds.
    #[arg(long, env = "BOUNDLESS_TIMEOUT")]
    pub timeout: Option<u32>,

    /// Ramp-up period in seconds.
    #[arg(long, env = "BOUNDLESS_RAMP_UP_PERIOD")]
    pub ramp_up_period: Option<u32>,
}

/// Pico-specific prover arguments.
#[cfg(feature = "pico")]
#[derive(Args, Clone)]
pub struct PicoArgs {
    #[clap(flatten)]
    pub shared: SharedProverArgs,

    /// Pico proving strategy: dev, local, or marketplace.
    #[arg(long = "strategy", value_enum, default_value = "marketplace")]
    pub strategy: PicoProvingStrategyCli,

    /// Base chain RPC URL for Brevis marketplace.
    #[arg(long = "pico-rpc-url", env = "PICO_RPC_URL")]
    pub pico_rpc_url: Option<String>,

    /// Wallet private key for Brevis marketplace transactions (hex-encoded).
    #[arg(long = "pico-prover-key", env = "PICO_PROVER_KEY")]
    pub prover_key: Option<String>,

    /// URL where the Pico ELF binary is hosted (e.g., IPFS).
    #[arg(long = "elf-url", env = "PICO_PROGRAM_URL")]
    pub elf_url: Option<String>,

    /// URL where input data is hosted (optional, for large inputs).
    #[arg(long = "input-url")]
    pub input_url: Option<String>,

    /// Maximum fee in BREV tokens (wei). Auto-estimated if not set.
    #[arg(long = "max-fee")]
    pub max_fee: Option<u128>,

    /// Fee multiplier for auto-estimation (default: 3.0).
    #[arg(long = "fee-multiplier")]
    pub fee_multiplier: Option<f64>,

    /// Minimum prover stake required (wei). Queried on-chain if not set.
    #[arg(long = "min-stake")]
    pub min_stake: Option<u128>,

    /// Request duration in seconds (default: 86400 = 24h).
    #[arg(long = "duration", default_value = "86400")]
    pub duration: u64,

    /// Poll interval in seconds for marketplace proof status (default: 30).
    #[arg(long = "poll-interval", default_value = "30")]
    pub poll_interval: u64,
}

/// Backend selection as a subcommand, with each variant carrying its own arguments.
#[derive(Subcommand, Clone)]
pub enum BackendSubcommand {
    /// Use the SP1 zkVM for proof generation.
    #[cfg(feature = "sp1")]
    Sp1(Sp1Args),

    /// Use the RISC0 zkVM for proof generation.
    #[cfg(feature = "risc0")]
    Risc0(Risc0Args),

    /// Use the Pico zkVM for proof generation.
    #[cfg(feature = "pico")]
    Pico(PicoArgs),
}

impl BackendSubcommand {
    /// Creates a prover configuration based on the selected backend.
    pub fn prover_config(&self) -> anyhow::Result<ProverConfig> {
        match self {
            #[cfg(feature = "sp1")]
            BackendSubcommand::Sp1(args) => {
                use amd_sev_snp_attestation_prover::{SP1ProverConfig, SP1ProvingStrategy};
                let strategy = if args.shared.dev {
                    SP1ProvingStrategy::Dev
                } else {
                    match args.strategy {
                        Sp1ProvingStrategyCli::Dev => SP1ProvingStrategy::Dev,
                        Sp1ProvingStrategyCli::Local => SP1ProvingStrategy::Local,
                        Sp1ProvingStrategyCli::Network => SP1ProvingStrategy::Network,
                    }
                };

                Ok(ProverConfig::sp1_with(SP1ProverConfig {
                    strategy,
                    private_key: args.sp1_private_key.clone(),
                    rpc_url: args.sp1_rpc_url.clone(),
                    signer: None,
                }))
            }

            #[cfg(feature = "risc0")]
            BackendSubcommand::Risc0(args) => {
                use amd_sev_snp_attestation_prover::{
                    program_risc0::BoundlessProofType, RiscZeroProverConfig,
                    RiscZeroProvingStrategy,
                };

                let strategy = if args.shared.dev {
                    RiscZeroProvingStrategy::Dev
                } else {
                    match args.strategy {
                        Risc0ProvingStrategyCli::Dev => RiscZeroProvingStrategy::Dev,
                        Risc0ProvingStrategyCli::Local => RiscZeroProvingStrategy::Local,
                        Risc0ProvingStrategyCli::Boundless => RiscZeroProvingStrategy::Boundless,
                    }
                };

                let proof_type = match args.proof_type {
                    BoundlessProofTypeCli::Merkle => BoundlessProofType::Merkle,
                    BoundlessProofTypeCli::Groth16 => BoundlessProofType::Groth16,
                };

                Ok(ProverConfig::risc0_with(RiscZeroProverConfig {
                    strategy,
                    rpc_url: args.boundless_rpc_url.clone(),
                    private_key: args.boundless_private_key.clone(),
                    verifier_program_url: args.verifier_program_url.clone(),
                    proof_type,
                    min_price: args.min_price,
                    max_price: args.max_price,
                    timeout: args.timeout,
                    ramp_up_period: args.ramp_up_period,
                }))
            }

            #[cfg(feature = "pico")]
            BackendSubcommand::Pico(args) => {
                use anyhow::anyhow;
                use amd_sev_snp_attestation_prover::{
                    MarketplaceConfig, PicoProverConfig, PicoProvingStrategy,
                };
                use std::time::{SystemTime, UNIX_EPOCH};

                let proving_strategy = if args.shared.dev {
                    PicoProvingStrategy::Dev
                } else {
                    match args.strategy {
                        PicoProvingStrategyCli::Dev => PicoProvingStrategy::Dev,
                        PicoProvingStrategyCli::Local => PicoProvingStrategy::Local,
                        PicoProvingStrategyCli::Marketplace => PicoProvingStrategy::Marketplace,
                    }
                };

                let marketplace = if proving_strategy == PicoProvingStrategy::Marketplace {
                    let elf_url = args
                        .elf_url
                        .clone()
                        .filter(|url| !url.trim().is_empty())
                        .ok_or_else(|| anyhow!("--elf-url is required for marketplace strategy"))?;

                    let now = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_secs();

                    Some(MarketplaceConfig {
                        rpc_url: args.pico_rpc_url.clone(),
                        private_key: args.prover_key.clone(),
                        elf_url,
                        input_url: args.input_url.clone(),
                        brevis_market_address: None,
                        brev_token_address: None,
                        staking_controller_address: None,
                        max_fee: args.max_fee,
                        fee_multiplier: args.fee_multiplier,
                        min_stake: args.min_stake,
                        deadline: now + args.duration,
                        nonce: now,
                        version: None,
                        poll_interval: Some(args.poll_interval),
                    })
                } else {
                    None
                };

                Ok(ProverConfig::pico_with(PicoProverConfig {
                    proving_strategy,
                    marketplace,
                }))
            }
        }
    }

    /// Creates a new `AmdSevSnpProver` instance with the configured settings.
    pub fn new_prover(
        &self,
        contract: Option<SnpVerifierContract>,
    ) -> anyhow::Result<AmdSevSnpProver> {
        Ok(AmdSevSnpProver::new(self.prover_config()?, contract))
    }
}

/// Command-line arguments for configuring smart contract interaction.
#[derive(Args, Clone)]
pub struct ContractArgs {
    /// The address of the SEVAgentAttestation contract.
    #[arg(long, env = "CONTRACT")]
    pub contract: Option<Address>,

    /// The RPC URL to connect to the Ethereum network.
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
