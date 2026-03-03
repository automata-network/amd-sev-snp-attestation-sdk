use std::fs::File;
use std::path::PathBuf;

use alloy_primitives::{hex, Bytes};
use pico_sdk::client::KoalaBearProverClient;
use pico_vm::{
    configs::stark_config::KoalaBearPoseidon2, emulator::stdin::EmulatorStdinBuilder,
    machine::keys::BaseVerifyingKey,
};

use crate::{RawProof, RawProofType};

pub(crate) fn gen_dev_proof(
    vk: BaseVerifyingKey<KoalaBearPoseidon2>,
    journal: Bytes,
) -> anyhow::Result<RawProof> {
    let blank: Vec<u8> = vec![];
    RawProof::from_proof(&(blank, vk), journal)
}

pub(crate) fn gen_local_proof(
    client: &KoalaBearProverClient,
    stdin_builder: EmulatorStdinBuilder<Vec<u8>, KoalaBearPoseidon2>,
    raw_proof_type: RawProofType,
    vk: BaseVerifyingKey<KoalaBearPoseidon2>,
    journal: Bytes,
) -> anyhow::Result<RawProof> {
    match raw_proof_type {
        RawProofType::Composite => {
            let (_riscv_proof, combine_proof) = client.prove_combine(stdin_builder)?;
            RawProof::from_proof(&(combine_proof, vk), journal)
        }
        RawProofType::Groth16 => {
            let output_path = PathBuf::from("evm_proof_artifacts");
            std::fs::create_dir_all(&output_path)?;

            // Setup is needed if vm_pk does not exist.
            let vm_pk_path = output_path.join("vm_pk");
            let need_setup = !vm_pk_path.exists();

            client.prove_evm(stdin_builder, need_setup, &output_path, "kb")?;

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
}
