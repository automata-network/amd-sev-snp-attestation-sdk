//! Zero-knowledge proof program abstraction
//!
//! This module defines the core traits and configuration structures for working with
//! zero-knowledge proof programs.
//! It provides a unified interface for different ZK proof systems like RISC0 and SP1.

use alloy_primitives::{Bytes, B256};
use alloy_sol_types::{SolType, SolValue};
use anyhow::anyhow;
use serde::{de::DeserializeOwned, Deserialize, Serialize};

/// Base trait defining shared metadata and encoding behavior for zk programs.
pub trait ProgramBase: Send + Sync {
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

    /// Returns the identifier for this program which can be used by the on-chain verifier contract.
    fn program_id(&self) -> B256;

    /// Returns the identifier for verifying the composite proof. It's usually used on the aggregator program.
    fn verify_proof_id(&self) -> B256;
}

/// Trait for local proving paths.
pub trait LocalProver: ProgramBase {
    fn gen_proof_local(
        &self,
        input: &Self::Input,
        raw_proof_type: RawProofType,
        encoded_composite_proofs: Option<&[&Bytes]>,
    ) -> anyhow::Result<RawProof>;

    fn gen_proof_dev(
        &self,
        input: &Self::Input,
        raw_proof_type: RawProofType,
        encoded_composite_proofs: Option<&[&Bytes]>,
    ) -> anyhow::Result<RawProof>;
}

/// Trait for remote proving paths and image upload operations.
pub trait RemoteProver: ProgramBase {
    fn gen_proof_remote(
        &self,
        input: &Self::Input,
        raw_proof_type: RawProofType,
        encoded_composite_proofs: Option<&[&Bytes]>,
    ) -> anyhow::Result<RawProof>;

    fn upload_image_remote(&self) -> anyhow::Result<()>;
}

/// Facade trait used by `AmdSevSnpProver`.
pub trait Program: ProgramBase {
    fn upload_image(&self) -> anyhow::Result<()>;

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
