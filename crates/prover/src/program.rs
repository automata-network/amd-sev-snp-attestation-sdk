//! Zero-knowledge proof program abstraction
//!
//! This module defines the core traits and configuration structures for working with
//! zero-knowledge proof programs.
//! It provides a unified interface for different ZK proof systems like RISC0 and SP1.

use anyhow::anyhow;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use alloy_primitives::{Bytes, B256};
use alloy_sol_types::{SolType, SolValue};

/// Core trait defining the interface for zero-knowledge proof programs.
///
/// This trait provides a unified interface for different ZK proof systems with pre-defined
/// input and output types to generate zero-knowledge proofs.
///
/// Implementations of this trait must be thread-safe (`Send + Sync`) to support
/// concurrent proof generation and verification operations.
///
pub trait Program: Send + Sync {
    /// The input type for this ZK program, must be Solidity-encodable
    type Input: SolValue;

    /// The output type for this ZK program, must be Solidity-encodable
    type Output: SolValue;

    type ZkType;

    /// Returns the version string of the zk proof system.
    fn version(&self) -> &'static str;

    /// Returns the type of zero-knowledge co-processor this program uses.
    ///
    /// This identifies which ZK proof system the program
    /// is designed to work with.
    ///
    /// # Returns
    ///
    /// The ZK co-processor type enumeration value
    fn zktype(&self) -> Self::ZkType;

    /// Converts a raw proof into a format suitable for on-chain verification.
    ///
    /// This method transforms the bincode encoded proof representation into onchain verifiable proof bytes.
    /// It might be empty if the proof is not verifiable on-chain (e.g. FakeProof, CompositeProof).
    fn onchain_proof(&self, proof: &RawProof) -> anyhow::Result<Bytes>;

    /// Uploads the program image to a remote proving service.
    fn upload_image(&self, cfg: &RemoteProverConfig) -> anyhow::Result<()>;

    /// Returns the identifier for this program which can be used by the on-chain verifier contract.
    fn program_id(&self) -> B256;

    /// Returns the identifier for verifying the composite proof. It's usually used on the aggregator program.
    fn verify_proof_id(&self) -> B256;

    /// Generates a zero-knowledge proof for the given input.
    ///
    /// This is the core method that produces cryptographic proofs demonstrating
    /// the correct execution of the program on the provided input.
    ///
    /// # Arguments
    ///
    /// * `input` - The input data for proof generation
    /// * `raw_proof_type` - The type of proof to generate (e.g., Groth16, Composite)
    /// * `encoded_composite_proofs` - Optional composite proofs for aggregation scenarios
    ///
    /// # Examples
    ///
    /// ```ignore
    /// // Generate a composite proof
    /// let proof1 = program.gen_proof(&input, RawProofType::Composite, None)?;
    ///
    /// // Generate an aggregated proof
    /// let aggregated = program.gen_proof(&input, RawProofType::Groth16, Some(&[&proof1, &proof2]))?;
    /// ```
    fn gen_proof(
        &self,
        input: &Self::Input,
        raw_proof_type: RawProofType,
        encoded_composite_proofs: Option<&[&Bytes]>,
    ) -> anyhow::Result<RawProof>;
}

/// Configuration for remote proof generation services.
///
/// This structure contains the necessary credentials and endpoint information
/// to connect to remote proving services.
#[derive(Clone)]
pub struct RemoteProverConfig {
    /// The API endpoint URL for the remote proving service
    /// Optional since SP1 5.2+ includes a default mainnet endpoint
    pub api_url: Option<String>,
    /// The authentication key for accessing the remote proving service
    pub api_key: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum RawProofType {
    Groth16,
    Composite,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RawProof {
    pub encoded_proof: Bytes,
    pub journal: Bytes,
}

impl RawProof {
    pub fn from_proof<P>(proof: P, journal: Bytes) -> anyhow::Result<Self>
    where
        P: Serialize,
    {
        let encoded_proof = bincode::serialize(&proof)?.into();
        Ok(Self {
            journal,
            encoded_proof,
        })
    }

    pub fn decode_proof<P>(&self) -> anyhow::Result<P>
    where
        P: Serialize + DeserializeOwned,
    {
        bincode::deserialize(&self.encoded_proof)
            .map_err(|err| anyhow!("Failed to deserialize proof: {}", err))
    }

    pub fn decode_journal<J>(&self) -> anyhow::Result<J>
    where
        J: SolValue + From<<<J as SolValue>::SolType as SolType>::RustType>,
    {
        J::abi_decode(&self.journal).map_err(|err| anyhow!("Failed to decode journal: {}", err))
    }
}
