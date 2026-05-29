//! Proof management and verification operations.
//!
//! This module provides functionality for working with generated proofs including
//! on-chain verification, proof aggregation, and composite proof generation.

use std::path::PathBuf;

use alloy_primitives::{Bytes, B256};
use anyhow::anyhow;
use atakit_zk_types::ZkVmSelection;
use clap::{Args, Subcommand};
use contract_stub::ZkCoProcessorType;
use serde::{Deserialize, Serialize};

use crate::utils::ContractArgs;

/// Subcommands for proof-related operations.
#[derive(Subcommand)]
pub enum ProofCli {
    /// Verify a proof on-chain using smart contract
    VerifyOnChain(ProofVerifyOnChainCli),
}

impl ProofCli {
    /// Executes the appropriate proof subcommand.
    pub async fn run(&self) -> anyhow::Result<()> {
        match self {
            ProofCli::VerifyOnChain(cli) => cli.run().await,
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

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct OnchainProof {
    vm: ZkVmSelection,
    program_id: B256,
    proof: Bytes,
    journal: Bytes,
}

impl ProofVerifyOnChainCli {
    /// Executes on-chain proof verification.
    ///
    /// This method submits a proof to the smart contract for verification,
    /// ensuring the proof was generated correctly and corresponds to valid
    /// Nitro Enclave attestation data.
    pub async fn run(&self) -> anyhow::Result<()> {
        // Ensure contract configuration is provided
        let contract = self.contract.stub()?.ok_or_else(|| {
            anyhow!("No contract specified. Use --contract, --rpc-url to specify the contract.")
        })?;

        // Load and parse the proof file
        let proof: OnchainProof = serde_json::from_slice(&std::fs::read(&self.proof)?)?;
        let ty = match proof.vm {
            ZkVmSelection::Risc0 => ZkCoProcessorType::RiscZero,
            ZkVmSelection::Sp1 => ZkCoProcessorType::Succinct,
        };

        // Verify proof to contract for verification
        let result = contract
            .call_verify(ty, proof.proof.clone(), proof.journal.clone())
            .await?;
        dbg!(result);

        if self.submit_on_chain {
            let receipt = contract
                .submit_verify(ty, proof.proof, proof.journal)
                .await?
                .get_receipt()
                .await;
            println!("{:?}", receipt);
        }

        Ok(())
    }
}
