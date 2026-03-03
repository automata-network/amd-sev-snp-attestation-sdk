use std::marker::PhantomData;

use alloy_primitives::{Bytes, B256, U256};
use alloy_sol_types::SolValue;
use amd_sev_snp_attestation_verifier::stub::{VerifierInput, VerifierJournal, ZkCoProcessorType};
use anyhow::anyhow;
use ff::PrimeField as FfPrimeField;
use lazy_static::lazy_static;
use pico_methods::PICO_VERIFIER_ELF;
use pico_sdk::{client::KoalaBearProverClient, HashableKey};
use pico_vm::{configs::stark_config::KoalaBearPoseidon2, machine::keys::BaseVerifyingKey};
use sha2::{Digest, Sha256};

use crate::{
    program::{LocalProver, Program, ProgramBase, RemoteProver},
    RawProof, RawProofType,
};

mod local;
mod remote;

lazy_static! {
    pub static ref PICO_PROGRAM_VERIFIER: ProgramPico<VerifierInput, VerifierJournal> =
        ProgramPico::new(PICO_VERIFIER_ELF);
}

/// Proving strategy for Pico zkVM.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PicoProvingStrategy {
    Dev,
    Local,
    #[default]
    Marketplace,
}

/// Configuration for Brevis Prover Network marketplace on Base.
#[derive(Debug, Clone)]
pub struct MarketplaceConfig {
    /// Base chain RPC URL (chain ID 8453).
    pub rpc_url: Option<String>,
    /// Wallet private key for signing transactions (hex-encoded).
    pub private_key: Option<String>,
    /// URL where the ELF binary is hosted (e.g., IPFS).
    pub elf_url: String,
    /// URL where input data is hosted (optional, for large inputs).
    pub input_url: Option<String>,
    /// BrevisMarket contract address (defaults to Base mainnet).
    pub brevis_market_address: Option<String>,
    /// BREV token contract address (defaults to Base mainnet).
    pub brev_token_address: Option<String>,
    /// StakingController contract address (defaults to Base mainnet).
    pub staking_controller_address: Option<String>,
    /// Maximum fee in BREV tokens (wei). If None, auto-estimated from on-chain stats.
    pub max_fee: Option<u128>,
    /// Multiplier applied to the estimated average fee when auto-estimating max_fee.
    pub fee_multiplier: Option<f64>,
    /// Minimum prover stake required (wei). If None, queried from StakingController.minSelfStake().
    pub min_stake: Option<u128>,
    /// Deadline as unix timestamp (computed from duration at submission time).
    pub deadline: u64,
    /// Unique nonce per request (auto-generated if not provided).
    pub nonce: u64,
    /// Pico verifier version (default 0).
    pub version: Option<u32>,
    /// Poll interval in seconds for checking proof status (default 30).
    pub poll_interval: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct PicoProverConfig {
    pub proving_strategy: PicoProvingStrategy,
    pub marketplace: Option<MarketplaceConfig>,
}

impl Default for PicoProverConfig {
    fn default() -> Self {
        let proving_strategy = if std::env::var("PICO_DEV_MODE").ok().as_deref() == Some("1") {
            PicoProvingStrategy::Dev
        } else {
            match std::env::var("PICO_STRATEGY").ok().as_deref() {
                Some("dev") => PicoProvingStrategy::Dev,
                Some("local") => PicoProvingStrategy::Local,
                _ => PicoProvingStrategy::Marketplace,
            }
        };

        PicoProverConfig {
            proving_strategy,
            marketplace: None,
        }
    }
}

#[derive(Clone)]
pub struct ProgramPico<Input, Output> {
    elf: &'static [u8],
    config: PicoProverConfig,
    _marker: PhantomData<(Input, Output)>,
}

impl<Input, Output> ProgramPico<Input, Output> {
    pub fn new(elf: &'static [u8]) -> Self {
        ProgramPico {
            elf,
            config: PicoProverConfig::default(),
            _marker: PhantomData,
        }
    }

    pub fn with_config(&self, config: PicoProverConfig) -> Self {
        ProgramPico {
            elf: self.elf,
            config,
            _marker: PhantomData,
        }
    }

    pub(crate) fn elf(&self) -> &'static [u8] {
        self.elf
    }

    pub(crate) fn config(&self) -> &PicoProverConfig {
        &self.config
    }

    /// Compute the 32-byte verification key for marketplace submission.
    pub(crate) fn compute_vk_bytes(&self) -> [u8; 32] {
        let client = KoalaBearProverClient::new(self.elf);
        let vk = client.riscv_vk().clone();
        let vk_digest_bn254 = vk.hash_bn254();
        let mut result = [0u8; 32];
        result.copy_from_slice(vk_digest_bn254.value.to_repr().as_ref());
        result.reverse(); // to_repr() is LE; convert to BE.
        result
    }

    /// Compute SHA-256 digest of public values buffer, then mask top 3 bits for BN254 field.
    pub(crate) fn compute_public_values_digest(buf: &[u8]) -> [u8; 32] {
        let hash = Sha256::digest(buf);
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&hash);
        digest[0] &= 0x1F;
        digest
    }

    fn gen_proof_for_strategy(
        &self,
        strategy: PicoProvingStrategy,
        input: &Input,
        raw_proof_type: RawProofType,
        _encoded_composite_proofs: Option<&[&Bytes]>,
    ) -> anyhow::Result<RawProof>
    where
        Input: SolValue,
    {
        let client = KoalaBearProverClient::new(self.elf);
        let mut stdin_builder = client.new_stdin_builder();
        stdin_builder.write_slice(&input.abi_encode());

        let vk = client.riscv_vk().clone();
        let (reports, pv_stream) = client.emulate(stdin_builder.clone());
        let cycles = reports.last().map(|r| r.current_cycle).unwrap_or(0);
        println!("Pico zkVM Emulation completed in {} cycles", cycles);

        let journal: Bytes = pv_stream.into();
        let pv_raw_bytes = journal.to_vec();

        match strategy {
            PicoProvingStrategy::Dev => local::gen_dev_proof(vk, journal),
            PicoProvingStrategy::Local => {
                local::gen_local_proof(&client, stdin_builder, raw_proof_type, vk, journal)
            }
            PicoProvingStrategy::Marketplace => remote::gen_marketplace_proof(
                self,
                stdin_builder,
                raw_proof_type,
                vk,
                journal,
                &pv_raw_bytes,
            ),
        }
    }
}

impl<Input, Output> ProgramBase for ProgramPico<Input, Output>
where
    Input: SolValue + Send + Sync,
    Output: SolValue + Send + Sync,
{
    type Input = Input;
    type Output = Output;
    type ZkType = ZkCoProcessorType;

    fn version(&self) -> &'static str {
        "v1.2.2"
    }

    fn zktype(&self) -> ZkCoProcessorType {
        ZkCoProcessorType::Pico
    }

    fn onchain_proof(&self, proof: &RawProof) -> anyhow::Result<Bytes> {
        if check_encoded_proof_is_empty(&proof.encoded_proof) {
            return Ok(Bytes::new());
        }

        let (proof, _) = proof.decode_proof::<(Vec<u8>, BaseVerifyingKey<KoalaBearPoseidon2>)>()?;
        let proof_elements: Vec<U256> = proof.chunks(32).take(8).map(U256::from_be_slice).collect();

        let proof_array: [U256; 8] = proof_elements
            .try_into()
            .map_err(|_| anyhow!("Expected exactly 8 proof elements"))?;
        Ok(proof_array.abi_encode().into())
    }

    fn program_id(&self) -> B256 {
        let client = KoalaBearProverClient::new(self.elf);
        let vk = client.riscv_vk();
        let vk_digest_bn254 = vk.hash_bn254();
        let mut result = [0u8; 32];
        result.copy_from_slice(vk_digest_bn254.value.to_repr().as_ref());
        result.reverse();
        B256::from(result)
    }

    fn verify_proof_id(&self) -> B256 {
        let client = KoalaBearProverClient::new(self.elf);
        let vk = client.riscv_vk();
        let vk_digest: [u32; 8] = vk.hash_u32();
        B256::new(unsafe { std::mem::transmute(vk_digest) })
    }
}

impl<Input, Output> LocalProver for ProgramPico<Input, Output>
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
        self.gen_proof_for_strategy(
            PicoProvingStrategy::Local,
            input,
            raw_proof_type,
            encoded_composite_proofs,
        )
    }

    fn gen_proof_dev(
        &self,
        input: &Self::Input,
        raw_proof_type: RawProofType,
        encoded_composite_proofs: Option<&[&Bytes]>,
    ) -> anyhow::Result<RawProof> {
        self.gen_proof_for_strategy(
            PicoProvingStrategy::Dev,
            input,
            raw_proof_type,
            encoded_composite_proofs,
        )
    }
}

impl<Input, Output> RemoteProver for ProgramPico<Input, Output>
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
        self.gen_proof_for_strategy(
            PicoProvingStrategy::Marketplace,
            input,
            raw_proof_type,
            encoded_composite_proofs,
        )
    }

    fn upload_image_remote(&self) -> anyhow::Result<()> {
        remote::upload_image(self)
    }
}

impl<Input, Output> Program for ProgramPico<Input, Output>
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
        self.gen_proof_for_strategy(
            self.config.proving_strategy,
            input,
            raw_proof_type,
            encoded_composite_proofs,
        )
    }
}

fn check_encoded_proof_is_empty(encoded_proof: &Bytes) -> bool {
    if encoded_proof.len() < 8 {
        return true;
    }

    // bincode serializes the proof with an 8-byte length prefix.
    let proof_len = u64::from_le_bytes(
        encoded_proof[0..8]
            .try_into()
            .expect("Failed to read proof length"),
    ) as usize;

    proof_len == 0
}
