use alloy_primitives::Bytes;
use risc0_zkvm::{
    default_executor, default_prover, Digest, ExecutorEnv, InnerReceipt, Prover, ProverOpts,
    Receipt, ReceiptClaim,
};

use crate::{RawProof, RawProofType};

use super::ProgramRisc0;

pub(crate) fn gen_proof_local<Input, Output>(
    program: &ProgramRisc0<Input, Output>,
    input_bytes: &[u8],
    raw_proof_type: RawProofType,
    _encoded_composite_proofs: Option<&[&Bytes]>,
) -> anyhow::Result<RawProof> {
    gen_local_single_proof(program, input_bytes, raw_proof_type)
}

pub(crate) fn gen_proof_dev<Input, Output>(
    program: &ProgramRisc0<Input, Output>,
    input_bytes: &[u8],
    _raw_proof_type: RawProofType,
    _encoded_composite_proofs: Option<&[&Bytes]>,
) -> anyhow::Result<RawProof> {
    gen_dev_single_proof(program, input_bytes)
}

fn gen_local_single_proof<Input, Output>(
    program: &ProgramRisc0<Input, Output>,
    input_bytes: &[u8],
    raw_proof_type: RawProofType,
) -> anyhow::Result<RawProof> {
    let env = ExecutorEnv::builder().write_slice(input_bytes).build()?;
    let opts = match raw_proof_type {
        RawProofType::Composite => ProverOpts::composite(),
        RawProofType::Groth16 => ProverOpts::groth16(),
    };

    let receipt = default_prover()
        .prove_with_opts(env, program.elf(), &opts)?
        .receipt;

    let journal: Bytes = receipt.journal.bytes.clone().into();
    RawProof::from_proof(&receipt, journal)
}

/// Dev mode: execute zkVM without proof generation.
/// Creates a FakeReceipt so the proof can be deserialized downstream.
fn gen_dev_single_proof<Input, Output>(
    program: &ProgramRisc0<Input, Output>,
    input_bytes: &[u8],
) -> anyhow::Result<RawProof> {
    let env = ExecutorEnv::builder().write_slice(input_bytes).build()?;

    let executor = default_executor();
    let session = executor.execute(env, program.elf())?;

    let journal: Bytes = session.journal.bytes.clone().into();

    let image_id = Digest::new(program.image_id());
    let claim = ReceiptClaim::ok(image_id, session.journal.bytes.clone());
    let receipt = Receipt::new(
        InnerReceipt::Fake(risc0_zkvm::FakeReceipt::new(claim)),
        session.journal.bytes,
    );
    RawProof::from_proof(&receipt, journal)
}
