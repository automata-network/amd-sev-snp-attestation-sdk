use sp1_sdk::{ProverClient, SP1Stdin};

use super::ProgramSP1;
use crate::{RawProof, RawProofType};

pub(crate) fn gen_raw_proof<Input, Output>(
    program: &ProgramSP1<Input, Output>,
    stdin: SP1Stdin,
    raw_proof_type: RawProofType,
    mock: bool,
) -> anyhow::Result<RawProof> {
    let prover = if mock {
        ProverClient::builder().mock().build()
    } else {
        ProverClient::builder().cpu().build()
    };

    let builder = prover.prove(program.pk(), &stdin);
    let builder = match raw_proof_type {
        RawProofType::Composite => builder.compressed(),
        RawProofType::Groth16 => builder.groth16(),
    };
    let proof = builder.run()?;

    RawProof::from_proof(
        &(proof.proof, program.vk()),
        proof.public_values.to_vec().into(),
    )
}
