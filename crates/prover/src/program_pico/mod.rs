use std::marker::PhantomData;

use alloy_primitives::{Bytes, B256, U256};
use alloy_sol_types::SolValue;
use amd_sev_snp_attestation_verifier::stub::{VerifierInput, VerifierJournal, ZkCoProcessorType};
use anyhow::anyhow;
use lazy_static::lazy_static;
use p3_field::PrimeField;
use pico_methods::PICO_VERIFIER_ELF;
use pico_sdk::{client::KoalaBearProverClient, HashableKey};
use pico_vm::{
    configs::stark_config::KoalaBearPoseidon2,
    machine::keys::BaseVerifyingKey,
};

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PicoProvingStrategy {
    Dev,
    #[default]
    Local,
    Marketplace,
}

#[derive(Debug, Clone, Default)]
pub struct MarketplaceConfigPlaceholder;

#[derive(Debug, Clone)]
pub struct PicoProverConfig {
    pub proving_strategy: PicoProvingStrategy,
    pub marketplace: Option<MarketplaceConfigPlaceholder>,
}

impl Default for PicoProverConfig {
    fn default() -> Self {
        let proving_strategy = if std::env::var("PICO_DEV_MODE").ok().as_deref() == Some("1") {
            PicoProvingStrategy::Dev
        } else {
            match std::env::var("PICO_STRATEGY").ok().as_deref() {
                Some("marketplace") => PicoProvingStrategy::Marketplace,
                Some("dev") => PicoProvingStrategy::Dev,
                _ => PicoProvingStrategy::Local,
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
        let (cycle, pv_stream) = client.emulate(stdin_builder.clone());
        println!("Pico zkVM Emulation completed in {} cycles", cycle);

        let journal: Bytes = pv_stream.into();

        match strategy {
            PicoProvingStrategy::Dev => local::gen_dev_proof(vk, journal),
            PicoProvingStrategy::Local => {
                local::gen_local_proof(&client, stdin_builder, raw_proof_type, vk, journal)
            }
            PicoProvingStrategy::Marketplace => {
                remote::gen_marketplace_proof(self, stdin_builder, raw_proof_type, vk, journal)
            }
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
        "v1.1.6"
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
        let vk_bytes = vk_digest_bn254.as_canonical_biguint().to_bytes_be();
        let mut result = [0u8; 32];
        result[1..].copy_from_slice(&vk_bytes);
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
