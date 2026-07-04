pub mod marketplace;

use alloy_primitives::Bytes;
use anyhow::anyhow;
use boundless_market::{storage::storage_provider_from_env, StorageProvider};
use pico_vm::{
    configs::stark_config::KoalaBearPoseidon2, emulator::stdin::EmulatorStdinBuilder,
    machine::keys::BaseVerifyingKey,
};

use crate::{utils::block_on, RawProof, RawProofType};

use super::ProgramPico;

pub(crate) fn gen_marketplace_proof<Input, Output>(
    program: &ProgramPico<Input, Output>,
    stdin_builder: EmulatorStdinBuilder<Vec<u8>, KoalaBearPoseidon2>,
    raw_proof_type: RawProofType,
    vk: BaseVerifyingKey<KoalaBearPoseidon2>,
    journal: Bytes,
    pv_raw_bytes: &[u8],
) -> anyhow::Result<RawProof> {
    if matches!(raw_proof_type, RawProofType::Composite) {
        return Err(anyhow!(
            "Marketplace proving only supports Groth16 proofs, not Composite. \
             Batch aggregation requires local proving."
        ));
    }

    let marketplace_config =
        program.config().marketplace.as_ref().ok_or_else(|| {
            anyhow!("Marketplace config is required when using marketplace strategy")
        })?;

    let input_bytes = bincode::serialize(&stdin_builder)?;
    let vk_bytes = program.compute_vk_bytes();
    let pv_digest = ProgramPico::<Input, Output>::compute_public_values_digest(pv_raw_bytes);

    println!("Submitting proof to Brevis Prover Network marketplace...");
    let proof_bytes = block_on(marketplace::prove_with_marketplace(
        program.elf(),
        &input_bytes,
        vk_bytes,
        pv_digest,
        marketplace_config,
    ))?;

    RawProof::from_proof(&(proof_bytes, vk), journal)
}

pub(crate) fn upload_image<Input, Output>(
    program: &ProgramPico<Input, Output>,
) -> anyhow::Result<()> {
    block_on(async {
        let storage_provider = storage_provider_from_env().map_err(|e| {
            anyhow!("Failed to get storage provider (check PINATA_JWT env var): {e}")
        })?;

        let elf_url = storage_provider
            .upload_input(program.elf())
            .await
            .map_err(|e| anyhow!("Failed to upload Pico ELF to Pinata/IPFS: {e}"))?;

        tracing::info!("Uploaded Pico image to storage: {}", elf_url);
        Ok(())
    })
}
