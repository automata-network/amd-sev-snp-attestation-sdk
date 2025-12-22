//! Proof management and verification operations.
//!
//! This module provides functionality for working with generated proofs including
//! on-chain verification, proof aggregation, and composite proof generation.

use std::path::PathBuf;

use amd_sev_snp_attestation_prover::{utils::block_on, OnchainProof};
use anyhow::anyhow;
use clap::{Args, Subcommand};

use crate::utils::ContractArgs;

/// Subcommands for proof-related operations.
#[derive(Subcommand)]
pub enum ProofCli {
    /// Verify a proof on-chain using smart contract
    VerifyOnChain(ProofVerifyOnChainCli),
}

impl ProofCli {
    /// Executes the appropriate proof subcommand.
    pub fn run(&self) -> anyhow::Result<()> {
        match self {
            ProofCli::VerifyOnChain(cli) => cli.run(),
        }
    }
}

/// Arguments for verifying proofs on-chain through smart contracts.
#[derive(Args)]
pub struct ProofVerifyOnChainCli {
    /// Path to the proof file to verify
    #[clap(long)]
    proof: PathBuf,

    /// Smart contract configuration for verification
    #[clap(flatten)]
    contract: ContractArgs,

    #[clap(long)]
    submit_on_chain: bool,
}

impl ProofVerifyOnChainCli {
    /// Executes on-chain proof verification.
    ///
    /// This method submits a proof to the smart contract for verification,
    /// ensuring the proof was generated correctly and corresponds to valid
    /// Nitro Enclave attestation data.
    pub fn run(&self) -> anyhow::Result<()> {
        // Ensure contract configuration is provided
        let contract = self.contract.stub()?.ok_or_else(|| {
            anyhow!("No contract specified. Use --contract, --rpc-url to specify the contract.")
        })?;

        // Load and parse the proof file
        let proof = OnchainProof::decode_json(&std::fs::read(&self.proof)?)?;

        // Validate that the proof contains on-chain verification data
        if proof.onchain_proof.len() == 0 {
            return Err(anyhow::anyhow!(
                "Proof does not contain an on-chain proof, unable to submit."
            ));
        }

        // Verify proof to contract for verification
        let result = block_on(contract.verify_proof(&proof))?;
        dbg!(result);

        if self.submit_on_chain {
            let receipt = block_on(contract.submit_proof(&proof))?;
            dbg!(receipt);
        }

        Ok(())
    }
}
