use std::marker::PhantomData;
use std::time::Duration;

use alloy_primitives::{Bytes, B256};
use alloy_sol_types::SolValue;
use amd_sev_snp_attestation_verifier::stub::{VerifierInput, VerifierJournal, ZkCoProcessorType};
use anyhow::{anyhow, Context};
use lazy_static::lazy_static;
use risc0_ethereum_contracts::{groth16, receipt::decode_seal_with_claim};
use risc0_methods::{RISC0_VERIFIER_ELF, RISC0_VERIFIER_ID};
use risc0_zkvm::{Digest, InnerReceipt, Receipt, ReceiptClaim, VERSION};

use crate::{
    program::{LocalProver, Program, ProgramBase, RemoteProver},
    RawProof, RawProofType,
};

pub mod boundless;
mod local;

lazy_static! {
    pub static ref RISC0_PROGRAM_VERIFIER: ProgramRisc0<VerifierInput, VerifierJournal> =
        ProgramRisc0::new(RISC0_VERIFIER_ELF, *RISC0_VERIFIER_ID);
}

/// Proof type for Boundless network proving.
#[derive(Debug, Clone, Copy, Default)]
pub enum BoundlessProofType {
    /// Groth16 proof - on-chain verifiable.
    #[default]
    Groth16,
    /// Merkle proof.
    Merkle,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum RiscZeroProvingStrategy {
    Dev,
    Local,
    #[default]
    Boundless,
}

#[derive(Debug, Clone)]
pub struct RiscZeroProverConfig {
    pub strategy: RiscZeroProvingStrategy,
    /// Boundless RPC URL (env: BOUNDLESS_RPC_URL)
    pub rpc_url: Option<String>,
    /// Wallet private key hex (env: BOUNDLESS_PRIVATE_KEY)
    pub private_key: Option<String>,
    /// Optional verifier program URL for pre-uploaded ELF (env: BOUNDLESS_VERIFIER_PROGRAM_URL)
    pub verifier_program_url: Option<String>,
    /// Proof type: Groth16 or Merkle (default: Groth16)
    pub proof_type: BoundlessProofType,
    /// Minimum price in wei per cycle
    pub min_price: Option<u128>,
    /// Maximum price in wei per cycle
    pub max_price: Option<u128>,
    /// Timeout in seconds
    pub timeout: Option<u32>,
    /// Ramp-up period in seconds
    pub ramp_up_period: Option<u32>,
}

impl Default for RiscZeroProverConfig {
    fn default() -> Self {
        let strategy = match std::env::var("RISC0_STRATEGY").ok().as_deref() {
            Some("dev") => RiscZeroProvingStrategy::Dev,
            Some("local") => RiscZeroProvingStrategy::Local,
            _ => RiscZeroProvingStrategy::Boundless,
        };

        RiscZeroProverConfig {
            strategy,
            rpc_url: std::env::var("BOUNDLESS_RPC_URL").ok(),
            private_key: std::env::var("BOUNDLESS_PRIVATE_KEY").ok(),
            verifier_program_url: std::env::var("BOUNDLESS_VERIFIER_PROGRAM_URL").ok(),
            proof_type: BoundlessProofType::default(),
            min_price: std::env::var("BOUNDLESS_MIN_PRICE")
                .ok()
                .and_then(|s| s.parse().ok()),
            max_price: std::env::var("BOUNDLESS_MAX_PRICE")
                .ok()
                .and_then(|s| s.parse().ok()),
            timeout: std::env::var("BOUNDLESS_TIMEOUT")
                .ok()
                .and_then(|s| s.parse().ok()),
            ramp_up_period: std::env::var("BOUNDLESS_RAMP_UP_PERIOD")
                .ok()
                .and_then(|s| s.parse().ok()),
        }
    }
}

impl RiscZeroProverConfig {
    pub(crate) const DEFAULT_MIN_PRICE_GWEI: &'static str = "0.0001";
    pub(crate) const DEFAULT_MAX_PRICE_GWEI: &'static str = "0.001";
    pub(crate) const DEFAULT_COLLATERAL_ETH: &'static str = "10";
    pub(crate) const DEFAULT_TIMEOUT_BUFFER: u32 = 600;
    pub(crate) const DEFAULT_POLL_INTERVAL_SECS: u64 = 5;

    /// Get effective min price (config or default: 0.0001 gwei).
    pub fn effective_min_price(&self) -> boundless::U256 {
        self.min_price
            .map(boundless::U256::from)
            .unwrap_or_else(|| {
                boundless::parse_units(Self::DEFAULT_MIN_PRICE_GWEI, "gwei")
                    .unwrap()
                    .into()
            })
    }

    /// Get effective max price (config or default: 0.001 gwei).
    pub fn effective_max_price(&self) -> boundless::U256 {
        self.max_price
            .map(boundless::U256::from)
            .unwrap_or_else(|| {
                boundless::parse_units(Self::DEFAULT_MAX_PRICE_GWEI, "gwei")
                    .unwrap()
                    .into()
            })
    }

    /// Get effective collateral (default: 10 ETH).
    pub fn effective_collateral(&self) -> boundless::U256 {
        boundless::parse_units(Self::DEFAULT_COLLATERAL_ETH, "ether")
            .unwrap()
            .into()
    }

    /// Get effective timeout with buffer.
    pub fn effective_timeout(&self) -> Option<(u32, u32)> {
        self.timeout.map(|t| (t, t + Self::DEFAULT_TIMEOUT_BUFFER))
    }

    /// Get poll interval for waiting on fulfillment.
    pub fn poll_interval(&self) -> Duration {
        Duration::from_secs(Self::DEFAULT_POLL_INTERVAL_SECS)
    }
}

#[derive(Clone)]
pub struct ProgramRisc0<Input, Output> {
    elf: &'static [u8],
    image_id: [u32; 8],
    config: RiscZeroProverConfig,
    _marker: PhantomData<(Input, Output)>,
}

impl<Input, Output> ProgramRisc0<Input, Output> {
    pub fn new(elf: &'static [u8], image_id: [u32; 8]) -> Self {
        ProgramRisc0 {
            elf,
            image_id,
            config: RiscZeroProverConfig::default(),
            _marker: PhantomData,
        }
    }

    pub fn with_config(&self, config: RiscZeroProverConfig) -> Self {
        Self {
            elf: self.elf,
            image_id: self.image_id,
            config,
            _marker: PhantomData,
        }
    }

    pub(crate) fn elf(&self) -> &'static [u8] {
        self.elf
    }

    pub(crate) fn image_id(&self) -> [u32; 8] {
        self.image_id
    }

    pub(crate) fn config(&self) -> &RiscZeroProverConfig {
        &self.config
    }

    /// Construct a Receipt from Boundless fulfillment data.
    /// The seal should include the 4-byte selector prefix followed by ABI-encoded proof.
    pub(crate) fn construct_receipt(
        seal: Vec<u8>,
        journal: Vec<u8>,
        image_id: Digest,
    ) -> anyhow::Result<Receipt> {
        // Handle empty seals (dev mode) - create FakeReceipt.
        if seal.is_empty() {
            let claim = ReceiptClaim::ok(image_id, journal.clone());
            return Ok(Receipt::new(
                InnerReceipt::Fake(risc0_zkvm::FakeReceipt::new(claim)),
                journal,
            ));
        }

        let claim = ReceiptClaim::ok(image_id, journal.clone());
        let receipt = decode_seal_with_claim(alloy_primitives::Bytes::from(seal), claim, journal)
            .context("Failed to decode seal")?;

        receipt
            .receipt()
            .cloned()
            .ok_or_else(|| anyhow!("Expected base receipt, got set inclusion receipt"))
    }
}

impl<Input, Output> ProgramBase for ProgramRisc0<Input, Output>
where
    Input: SolValue + Send + Sync,
    Output: SolValue + Send + Sync,
{
    type Input = Input;
    type Output = Output;
    type ZkType = ZkCoProcessorType;

    fn version(&self) -> &'static str {
        VERSION
    }

    fn zktype(&self) -> ZkCoProcessorType {
        ZkCoProcessorType::RiscZero
    }

    fn onchain_proof(&self, proof: &RawProof) -> anyhow::Result<Bytes> {
        if proof.encoded_proof.is_empty() {
            return Ok(Bytes::new());
        }

        let receipt = proof.decode_proof::<Receipt>()?;
        let encoded_proof = match &receipt.inner {
            InnerReceipt::Groth16(groth16_receipt) => groth16::encode(&groth16_receipt.seal)?,
            _ => vec![],
        };
        Ok(encoded_proof.into())
    }

    fn program_id(&self) -> B256 {
        B256::from_slice(Digest::new(self.image_id).as_bytes())
    }

    fn verify_proof_id(&self) -> B256 {
        self.program_id()
    }
}

impl<Input, Output> LocalProver for ProgramRisc0<Input, Output>
where
    Input: SolValue + Send + Sync,
    Output: SolValue + Send + Sync,
{
    fn gen_proof_local(
        &self,
        input: &Self::Input,
        raw_proof_type: RawProofType,
        encoded_composite_proofs: Option<&[&Bytes]>,
    ) -> anyhow::Result<RawProof> {
        let input_bytes = input.abi_encode();
        local::gen_proof_local(self, &input_bytes, raw_proof_type, encoded_composite_proofs)
    }

    fn gen_proof_dev(
        &self,
        input: &Self::Input,
        raw_proof_type: RawProofType,
        encoded_composite_proofs: Option<&[&Bytes]>,
    ) -> anyhow::Result<RawProof> {
        let input_bytes = input.abi_encode();
        local::gen_proof_dev(self, &input_bytes, raw_proof_type, encoded_composite_proofs)
    }
}

impl<Input, Output> RemoteProver for ProgramRisc0<Input, Output>
where
    Input: SolValue + Send + Sync,
    Output: SolValue + Send + Sync,
{
    fn gen_proof_remote(
        &self,
        input: &Self::Input,
        raw_proof_type: RawProofType,
        encoded_composite_proofs: Option<&[&Bytes]>,
    ) -> anyhow::Result<RawProof> {
        let input_bytes = input.abi_encode();
        boundless::gen_proof(self, &input_bytes, raw_proof_type, encoded_composite_proofs)
    }

    fn upload_image_remote(&self) -> anyhow::Result<()> {
        boundless::upload_image(self)
    }
}

impl<Input, Output> Program for ProgramRisc0<Input, Output>
where
    Input: SolValue + Send + Sync,
    Output: SolValue + Send + Sync,
{
    fn upload_image(&self) -> anyhow::Result<()> {
        self.upload_image_remote()
    }

    fn gen_proof(
        &self,
        input: &Self::Input,
        raw_proof_type: RawProofType,
        encoded_composite_proofs: Option<&[&Bytes]>,
    ) -> anyhow::Result<RawProof> {
        match self.config.strategy {
            RiscZeroProvingStrategy::Dev => {
                self.gen_proof_dev(input, raw_proof_type, encoded_composite_proofs)
            }
            RiscZeroProvingStrategy::Local => {
                self.gen_proof_local(input, raw_proof_type, encoded_composite_proofs)
            }
            RiscZeroProvingStrategy::Boundless => {
                self.gen_proof_remote(input, raw_proof_type, encoded_composite_proofs)
            }
        }
    }
}
