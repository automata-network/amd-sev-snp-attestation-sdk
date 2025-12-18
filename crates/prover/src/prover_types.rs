use alloy_primitives::{Bytes, B256};
use amd_sev_snp_attestation_verifier::stub::ZkCoProcessorType;
use anyhow::anyhow;
use serde::{Deserialize, Serialize};

use crate::{Program, RawProof};

/// Configuration enumeration for different zero-knowledge proof systems.
///
/// This enum allows users to select and configure which ZK proof system
/// to use for generating proofs of AWS Nitro Enclave attestations.
/// Each variant corresponds to a different zkVM implementation with
/// its own performance characteristics and features.
///
/// # Available Backends
///
/// - **SP1 (Succinct)**: High-performance zkVM with network proving support
/// - **RISC0**: Industrial-grade zkVM with Bonsai cloud proving
///
/// # Feature Flags
///
/// The availability of each variant depends on compile-time feature flags:
/// - `sp1` feature enables the Succinct variant
/// - `risc0` feature enables the RiscZero variant
#[derive(Debug, Clone)]
pub struct ProverConfig {
    pub default_trusted_certs_prefix_length: u8,
    pub skip_time_validity_check: bool,
    pub skip_contract_program_id_check: bool,
    pub system: ProverSystemConfig,
}

impl ProverConfig {
    #[cfg(feature = "risc0")]
    pub fn risc0() -> Self {
        Self::risc0_with(Default::default())
    }

    #[cfg(feature = "risc0")]
    pub fn risc0_with(cfg: crate::program_risc0::RiscZeroProverConfig) -> Self {
        Self {
            default_trusted_certs_prefix_length: Self::default_trusted_certs_prefix_length(),
            skip_time_validity_check: Self::skip_time_validity_check(),
            skip_contract_program_id_check: Self::skip_contract_program_id_check(),
            system: ProverSystemConfig::RiscZero(cfg),
        }
    }

    #[cfg(feature = "sp1")]
    pub fn sp1() -> Self {
        Self::sp1_with(Default::default())
    }

    #[cfg(feature = "sp1")]
    pub fn sp1_with(cfg: crate::program_sp1::SP1ProverConfig) -> Self {
        Self {
            default_trusted_certs_prefix_length: Self::default_trusted_certs_prefix_length(),
            skip_time_validity_check: Self::skip_time_validity_check(),
            skip_contract_program_id_check: Self::skip_contract_program_id_check(),
            system: ProverSystemConfig::Succinct(cfg),
        }
    }

    #[cfg(feature = "pico")]
    pub fn pico() -> Self {
        Self::pico_with(Default::default())
    }

    #[cfg(feature = "pico")]
    pub fn pico_with(cfg: crate::program_pico::PicoProverConfig) -> Self {
        Self {
            default_trusted_certs_prefix_length: Self::default_trusted_certs_prefix_length(),
            skip_time_validity_check: Self::skip_time_validity_check(),
            skip_contract_program_id_check: Self::skip_contract_program_id_check(),
            system: ProverSystemConfig::Pico(cfg),
        }
    }

    fn default_trusted_certs_prefix_length() -> u8 {
        std::env::var("DEFAULT_TRUSTED_CERTS_PREFIX_LENGTH")
            .ok()
            .and_then(|s| s.parse::<u8>().ok())
            .unwrap_or(1_u8)
    }

    fn skip_time_validity_check() -> bool {
        std::env::var("SKIP_TIME_VALIDITY_CHECK")
            .ok()
            .and_then(|s| s.parse::<bool>().ok())
            .unwrap_or(false)
    }

    fn skip_contract_program_id_check() -> bool {
        std::env::var("SKIP_CONTRACT_PROGRAM_ID_CHECK")
            .ok()
            .and_then(|s| s.parse::<bool>().ok())
            .unwrap_or(false)
    }
}

#[derive(Debug, Clone)]
pub enum ProverSystemConfig {
    #[cfg(feature = "sp1")]
    Succinct(crate::program_sp1::SP1ProverConfig),
    #[cfg(feature = "risc0")]
    RiscZero(crate::program_risc0::RiscZeroProverConfig),
    #[cfg(feature = "pico")]
    Pico(crate::program_pico::PicoProverConfig),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OnchainProof {
    pub zktype: ZkCoProcessorType,
    pub zkvm_version: String,
    pub program_id: ProgramId,
    pub raw_proof: RawProof,
    pub onchain_proof: Bytes,
}

impl OnchainProof {
    pub fn new(
        zktype: ZkCoProcessorType,
        zkvm_version: String,
        program_id: ProgramId,
        onchain_proof: Bytes,
        raw_proof: RawProof,
    ) -> Self {
        Self {
            zktype,
            zkvm_version,
            program_id,
            raw_proof,
            onchain_proof,
        }
    }

    pub fn new_from_program<P: Program<ZkType = ZkCoProcessorType> + ?Sized>(
        p: &P,
        program_id: ProgramId,
        raw_proof: RawProof,
    ) -> anyhow::Result<Self> {
        Ok(Self::new(
            p.zktype(),
            p.version().into(),
            program_id,
            p.onchain_proof(&raw_proof)?,
            raw_proof,
        ))
    }

    pub fn encode_json(&self) -> anyhow::Result<Vec<u8>> {
        serde_json::to_vec_pretty(self).map_err(|e| anyhow!("Failed to serialize proof: {}", e))
    }

    pub fn decode_json(data: &[u8]) -> anyhow::Result<Self> {
        serde_json::from_slice(data).map_err(|e| anyhow!("Failed to deserialize proof: {}", e))
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProgramId {
    pub verifier_id: B256,
    pub verify_proof_id: B256,
}

impl ProgramId {
    pub fn verify(&self, verifier_id: &B256) -> anyhow::Result<()> {
        if verifier_id != &self.verifier_id {
            return Err(anyhow!(
                "Program ID mismatch with on-chain config: want: {{verifierId={}}}, got: {{verifierId={}}})",
                verifier_id,
                self.verifier_id,
            ));
        }
        Ok(())
    }

    pub fn encode_json(&self, zk: ZkCoProcessorType) -> anyhow::Result<Vec<u8>> {
        let val = serde_json::to_value(self)?;
        let mut map = serde_json::Map::new();
        map.insert("program_id".into(), val);
        map.insert("zktype".into(), serde_json::to_value(&zk)?);
        serde_json::to_vec_pretty(&map)
            .map_err(|e| anyhow!("Failed to serialize program ID: {}", e))
    }
}
