use std::fs::File;
use std::marker::PhantomData;
use std::path::PathBuf;

use alloy_primitives::{hex, Bytes, B256, U256};
use alloy_sol_types::SolValue;
use anyhow::anyhow;
use amd_sev_snp_attestation_verifier::stub::{
    VerifierInput, VerifierJournal, ZkCoProcessorType,
};
use lazy_static::lazy_static;
use p3_field::PrimeField;
use pico_methods::PICO_VERIFIER_ELF;
use pico_sdk::{client::KoalaBearProverClient, HashableKey};
use pico_vm::{
    configs::stark_config::KoalaBearPoseidon2,
    emulator::stdin::EmulatorStdinBuilder,
    machine::keys::BaseVerifyingKey,
};

use crate::{
    program::{Program, RemoteProverConfig},
    RawProof, RawProofType,
};

lazy_static! {
    pub static ref PICO_PROGRAM_VERIFIER: ProgramPico<VerifierInput, VerifierJournal> =
        ProgramPico::new(PICO_VERIFIER_ELF);
}

#[derive(Debug, Clone)]
pub struct PicoProverConfig {
    // Empty for now, extensible for future options (e.g., backend selection)
}

impl Default for PicoProverConfig {
    fn default() -> Self {
        PicoProverConfig {}
    }
}

#[derive(Clone)]
pub struct ProgramPico<Input, Output> {
    elf: &'static [u8],
    _marker: PhantomData<(Input, Output)>,
}

impl<Input, Output> ProgramPico<Input, Output> {
    pub fn new(elf: &'static [u8]) -> Self {
        ProgramPico {
            elf,
            _marker: PhantomData,
        }
    }

    pub fn gen_raw_proof(
        &self,
        stdin_builder: EmulatorStdinBuilder<Vec<u8>, KoalaBearPoseidon2>,
        raw_proof_type: RawProofType,
    ) -> anyhow::Result<RawProof> {
        let client = KoalaBearProverClient::new(self.elf);
        let vk = client.riscv_vk();

        let dev_mode = std::env::var("PICO_DEV_MODE")
            .map(|v| v == "1")
            .unwrap_or(false);

        let (cycle, pv_stream) = client.emulate(stdin_builder.clone());
        println!("Pico zkVM Emulation completed in {} cycles", cycle);

        let journal: Bytes = pv_stream.into();

        if !dev_mode {
            match raw_proof_type {
                RawProofType::Composite => {
                    // prove_combine returns (riscv_proof, combine_proof)
                    let (_riscv_proof, combine_proof) = client.prove_combine(stdin_builder)?;
                    RawProof::from_proof(&(combine_proof, vk), journal)
                }
                RawProofType::Groth16 => {
                    // Use permanent artifacts directory
                    let output_path = PathBuf::from("evm_proof_artifacts");
                    std::fs::create_dir_all(&output_path)?;

                    // Check if setup is needed (vm_pk doesn't exist)
                    let vm_pk_path = output_path.join("vm_pk");
                    let need_setup = !vm_pk_path.exists();

                    // Prove with EVM backend (KoalaBear)
                    client.prove_evm(stdin_builder, need_setup, &output_path, "kb")?;

                    // Read proof.data - first 8 elements of 32-byte values
                    let proof_file = output_path.join("proof.data");
                    let proof_data: Vec<String> = serde_json::from_reader(File::open(proof_file)?)?;
                    let proof_bytes: Vec<u8> = proof_data[..8]
                        .iter()
                        .flat_map(|s| {
                            hex::decode(s.trim_start_matches("0x"))
                                .expect("Failed to decode proof hex string")
                        })
                        .collect();

                    RawProof::from_proof(&(proof_bytes, vk), journal)
                }
            }
        } else {
            let blank: Vec<u8> = vec![];
            RawProof::from_proof(&(blank, vk), journal)
        }
    }
}

impl<Input, Output> Program for ProgramPico<Input, Output>
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
        // Decode the 8 * 32-byte proof elements
        let proof_elements: Vec<U256> = proof
            .chunks(32)
            .take(8)
            .map(|chunk| U256::from_be_slice(chunk))
            .collect();

        // ABI encode as uint256[8]
        let proof_array: [U256; 8] = proof_elements
            .try_into()
            .map_err(|_| anyhow!("Expected exactly 8 proof elements"))?;
        Ok(proof_array.abi_encode().into())
    }

    fn upload_image(&self, _cfg: &RemoteProverConfig) -> anyhow::Result<()> {
        Err(anyhow!("Remote prover is not supported for Pico zkVM"))
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

    fn gen_proof(
        &self,
        input: &Self::Input,
        raw_proof_type: RawProofType,
        _encoded_composite_proofs: Option<&[&Bytes]>,
    ) -> anyhow::Result<RawProof> {
        let client = KoalaBearProverClient::new(self.elf);
        let mut stdin_builder = client.new_stdin_builder();

        // Write input
        stdin_builder.write_slice(&input.abi_encode());

        // Note: AMD SEV doesn't need composite proof aggregation for now
        // If needed in the future, we can add aggregator support here

        self.gen_raw_proof(stdin_builder, raw_proof_type)
    }
}

fn check_encoded_proof_is_empty(encoded_proof: &Bytes) -> bool {
    if encoded_proof.len() < 8 {
        return true;
    }

    // bincode serializes the proof with an 8-byte length prefix
    let proof_len = u64::from_le_bytes(
        encoded_proof[0..8]
            .try_into()
            .expect("Failed to read proof length"),
    ) as usize;

    proof_len == 0
}
