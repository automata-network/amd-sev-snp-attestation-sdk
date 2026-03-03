use alloy_primitives::Bytes;
use anyhow::anyhow;
use pico_vm::{
    configs::stark_config::KoalaBearPoseidon2, emulator::stdin::EmulatorStdinBuilder,
    machine::keys::BaseVerifyingKey,
};

use crate::{RawProof, RawProofType};

use super::ProgramPico;

pub(crate) fn gen_marketplace_proof<Input, Output>(
    _program: &ProgramPico<Input, Output>,
    _stdin_builder: EmulatorStdinBuilder<Vec<u8>, KoalaBearPoseidon2>,
    _raw_proof_type: RawProofType,
    _vk: BaseVerifyingKey<KoalaBearPoseidon2>,
    _journal: Bytes,
) -> anyhow::Result<RawProof> {
    Err(anyhow!(
        "Marketplace mode is reserved for the next task; use --pico-strategy local or --pico-strategy dev for now."
    ))
}

pub(crate) fn upload_image<Input, Output>(
    _program: &ProgramPico<Input, Output>,
) -> anyhow::Result<()> {
    Err(anyhow!(
        "Pico marketplace upload is reserved for the next task; only local/dev Pico proving is supported in this refactor."
    ))
}
