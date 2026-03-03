use std::marker::PhantomData;

use alloy_primitives::{hex::FromHex, Bytes, B256};
use alloy_sol_types::SolValue;
use amd_sev_snp_attestation_verifier::stub::{VerifierInput, VerifierJournal, ZkCoProcessorType};
use anyhow::anyhow;
use lazy_static::lazy_static;
use sp1_methods::{SP1_VERIFIER_ELF, SP1_VERIFIER_PK, SP1_VERIFIER_VK};
use sp1_sdk::{
    HashableKey, SP1Proof, SP1ProvingKey, SP1Stdin, SP1VerifyingKey, SP1_CIRCUIT_VERSION,
};

use crate::{
    program::{LocalProver, Program, ProgramBase, RemoteProver},
    RawProof, RawProofType,
};

mod local;
mod remote;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum SP1ProvingStrategy {
    Dev,
    Local,
    #[default]
    Network,
}

#[derive(Debug, Clone)]
pub struct SP1ProverConfig {
    pub strategy: SP1ProvingStrategy,
    pub private_key: Option<String>,
    pub rpc_url: Option<String>,
}

impl Default for SP1ProverConfig {
    fn default() -> Self {
        let strategy = match std::env::var("SP1_PROVER").ok().as_deref() {
            Some("mock") | Some("dev") => SP1ProvingStrategy::Dev,
            Some("local") | Some("cpu") => SP1ProvingStrategy::Local,
            _ => SP1ProvingStrategy::Network,
        };

        SP1ProverConfig {
            strategy,
            private_key: std::env::var("SP1_PRIVATE_KEY")
                .ok()
                .or_else(|| std::env::var("NETWORK_PRIVATE_KEY").ok()),
            rpc_url: std::env::var("SP1_RPC_URL")
                .ok()
                .or_else(|| std::env::var("NETWORK_RPC_URL").ok()),
        }
    }
}

lazy_static! {
    pub static ref SP1_PROGRAM_VERIFIER: ProgramSP1<VerifierInput, VerifierJournal> =
        ProgramSP1::new(SP1_VERIFIER_ELF, &SP1_VERIFIER_VK, &SP1_VERIFIER_PK);
}

#[derive(Clone)]
pub struct ProgramSP1<Input, Output> {
    vk: &'static SP1VerifyingKey,
    pk: &'static SP1ProvingKey,
    elf: &'static [u8],
    config: SP1ProverConfig,
    _marker: PhantomData<(Input, Output)>,
}

impl<Input, Output> ProgramSP1<Input, Output> {
    pub fn new(
        elf: &'static [u8],
        vk: &'static SP1VerifyingKey,
        pk: &'static SP1ProvingKey,
    ) -> Self {
        ProgramSP1 {
            vk,
            pk,
            elf,
            config: SP1ProverConfig::default(),
            _marker: PhantomData,
        }
    }

    pub fn with_config(&self, config: SP1ProverConfig) -> Self {
        Self {
            vk: self.vk,
            pk: self.pk,
            elf: self.elf,
            config,
            _marker: PhantomData,
        }
    }

    pub(crate) fn vk(&self) -> &'static SP1VerifyingKey {
        self.vk
    }

    pub(crate) fn pk(&self) -> &'static SP1ProvingKey {
        self.pk
    }

    pub(crate) fn elf(&self) -> &'static [u8] {
        self.elf
    }

    pub(crate) fn config(&self) -> &SP1ProverConfig {
        &self.config
    }

    fn build_stdin(
        &self,
        input: &Input,
        encoded_composite_proofs: Option<&[&Bytes]>,
    ) -> anyhow::Result<SP1Stdin>
    where
        Input: SolValue,
    {
        let mut stdin = SP1Stdin::new();
        stdin.write_vec(input.abi_encode());
        if let Some(encoded_composite_proofs) = encoded_composite_proofs {
            for proof in encoded_composite_proofs {
                let (proof, vk) = bincode::deserialize::<(SP1Proof, SP1VerifyingKey)>(&proof)?;
                let SP1Proof::Compressed(proof) = proof else {
                    return Err(anyhow!("Expected a compressed SP1 proof"));
                };
                stdin.write_proof(*proof, vk.vk);
            }
        }
        Ok(stdin)
    }
}

impl<Input, Output> ProgramBase for ProgramSP1<Input, Output>
where
    Input: SolValue + Send + Sync,
    Output: SolValue + Send + Sync,
{
    type Input = Input;
    type Output = Output;
    type ZkType = ZkCoProcessorType;

    fn version(&self) -> &'static str {
        SP1_CIRCUIT_VERSION
    }

    fn zktype(&self) -> ZkCoProcessorType {
        ZkCoProcessorType::Succinct
    }

    fn onchain_proof(&self, proof: &RawProof) -> anyhow::Result<Bytes> {
        let (sp1_proof, _) = proof.decode_proof::<(SP1Proof, SP1VerifyingKey)>()?;
        Ok(match sp1_proof {
            SP1Proof::Groth16(groth16_proof) => {
                if groth16_proof.encoded_proof.is_empty() {
                    return Ok(Bytes::new());
                }
                let proof_bytes = Bytes::from_hex(&groth16_proof.encoded_proof)?;
                [
                    groth16_proof.groth16_vkey_hash[..4].to_vec(),
                    proof_bytes.to_vec(),
                ]
                .concat()
                .into()
            }
            SP1Proof::Plonk(plonk_proof) => {
                if plonk_proof.encoded_proof.is_empty() {
                    return Ok(Bytes::new());
                }
                let proof_bytes = Bytes::from_hex(&plonk_proof.encoded_proof)?;
                [
                    plonk_proof.plonk_vkey_hash[..4].to_vec(),
                    proof_bytes.to_vec(),
                ]
                .concat()
                .into()
            }
            SP1Proof::Compressed(_) | SP1Proof::Core(_) => Bytes::new(),
        })
    }

    fn program_id(&self) -> B256 {
        self.vk.bytes32_raw().into()
    }

    fn verify_proof_id(&self) -> B256 {
        B256::new(unsafe { std::mem::transmute(self.vk.hash_u32()) })
    }
}

impl<Input, Output> LocalProver for ProgramSP1<Input, Output>
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
        let stdin = self.build_stdin(input, encoded_composite_proofs)?;
        local::gen_raw_proof(self, stdin, raw_proof_type, false)
    }

    fn gen_proof_dev(
        &self,
        input: &Self::Input,
        raw_proof_type: RawProofType,
        encoded_composite_proofs: Option<&[&Bytes]>,
    ) -> anyhow::Result<RawProof> {
        let stdin = self.build_stdin(input, encoded_composite_proofs)?;
        local::gen_raw_proof(self, stdin, raw_proof_type, true)
    }
}

impl<Input, Output> RemoteProver for ProgramSP1<Input, Output>
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
        let stdin = self.build_stdin(input, encoded_composite_proofs)?;
        remote::gen_raw_proof(self, stdin, raw_proof_type)
    }

    fn upload_image_remote(&self) -> anyhow::Result<()> {
        remote::upload_image(self)
    }
}

impl<Input, Output> Program for ProgramSP1<Input, Output>
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
            SP1ProvingStrategy::Dev => {
                self.gen_proof_dev(input, raw_proof_type, encoded_composite_proofs)
            }
            SP1ProvingStrategy::Local => {
                self.gen_proof_local(input, raw_proof_type, encoded_composite_proofs)
            }
            SP1ProvingStrategy::Network => {
                self.gen_proof_remote(input, raw_proof_type, encoded_composite_proofs)
            }
        }
    }
}
