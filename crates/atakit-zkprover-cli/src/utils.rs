//! Utility modules for CLI argument parsing and configuration.
//!
//! This module contains shared argument structures and helper functions
//! used across different CLI commands for configuring provers and smart contracts.

use alloy_primitives::{Address, Bytes};
use atakit_zk_prover::{
    NetworkConfig, ProverBackend, ProverConfig, Risc0NetworkConfig, Risc0StorageConfig,
    Sp1NetworkConfig, ZkProver,
};
use atakit_zk_types::ZkVmSelection;
use clap::{Args, ValueEnum};
use contract_stub::SnpVerifierContract;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum VmArg {
    Sp1,
    Risc0,
}

impl VmArg {
    pub(crate) fn selection(self) -> ZkVmSelection {
        match self {
            Self::Sp1 => ZkVmSelection::Sp1,
            Self::Risc0 => ZkVmSelection::Risc0,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum BackendArg {
    Mock,
    Cpu,
    Network,
}

/// Command-line arguments for configuring zero-knowledge proof system settings.
///
/// Supports both RISC0 and SP1 proof systems with their respective configuration options.
/// Only one prover type should be specified at a time.
#[derive(Args, Clone)]
pub struct ProverArgs {
    #[arg(long, value_enum)]
    pub vm: VmArg,

    #[arg(long, value_enum)]
    pub backend: BackendArg,

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

    #[arg(long, env = "PINATA_JWT")]
    pub risc0_pinata_jwt: Option<String>,
}

impl ProverArgs {
    /// Creates a prover configuration based on the specified arguments.
    pub fn prover_config(&self) -> anyhow::Result<ProverConfig> {
        let vm = self.vm.selection();
        let backend = match self.backend {
            BackendArg::Mock => ProverBackend::Mock,
            BackendArg::Cpu => ProverBackend::Cpu,
            BackendArg::Network => match vm {
                ZkVmSelection::Sp1 => {
                    ProverBackend::Network(NetworkConfig::Sp1(Sp1NetworkConfig {
                        private_key: self
                            .sp1_private_key
                            .as_deref()
                            .map(str::parse)
                            .transpose()?,
                        rpc_url: self.sp1_rpc_url.as_deref().map(str::parse).transpose()?,
                    }))
                }
                ZkVmSelection::Risc0 => {
                    let mut storage = None;
                    if let Some(risc0_pinata_jwt) = &self.risc0_pinata_jwt {
                        storage = Some(Risc0StorageConfig::Pinata {
                            jwt: risc0_pinata_jwt.clone(),
                            api_url: None,
                            gateway_url: None,
                        });
                    }
                    ProverBackend::Network(NetworkConfig::Risc0(Risc0NetworkConfig {
                        private_key: self
                            .boundless_private_key
                            .as_deref()
                            .map(str::parse)
                            .transpose()?,
                        rpc_url: self
                            .boundless_rpc_url
                            .as_deref()
                            .map(str::parse)
                            .transpose()?,
                        storage,
                        ..Risc0NetworkConfig::default()
                    }))
                }
            },
        };

        Ok(ProverConfig { vm, backend })
    }

    /// Creates a new `NitroEnclaveProver` instance with the configured settings.
    pub fn new_prover(&self) -> anyhow::Result<ZkProver> {
        Ok(ZkProver::new(self.prover_config()?))
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationReportWithVekCertChain {
    pub report: Bytes,
    pub vek_certs: Option<Vec<Bytes>>,
}

impl AttestationReportWithVekCertChain {
    pub fn decode(input: &[u8]) -> anyhow::Result<Self> {
        serde_json::from_slice(input).map_err(|e| anyhow::anyhow!("Failed to decode: {}", e))
    }
}
