use sp1_sdk::{ProveRequest, Prover, ProverClient, SP1Stdin};

use super::ProgramSP1;
use crate::utils::block_on;
use crate::{RawProof, RawProofType};

pub(crate) fn gen_raw_proof<Input, Output>(
    program: &ProgramSP1<Input, Output>,
    stdin: SP1Stdin,
    raw_proof_type: RawProofType,
    mock: bool,
) -> anyhow::Result<RawProof> {
    let proof = if mock {
        block_on(async {
            let prover = ProverClient::builder().mock().build().await;
            let builder = prover.prove(program.pk(), stdin);
            match raw_proof_type {
                RawProofType::Composite => builder.compressed().await,
                RawProofType::Groth16 => builder.groth16().await,
            }
        })?
    } else {
        block_on(async {
            let prover = ProverClient::builder().cpu().build().await;
            let builder = prover.prove(program.pk(), stdin);
            match raw_proof_type {
                RawProofType::Composite => builder.compressed().await,
                RawProofType::Groth16 => builder.groth16().await,
            }
        })?
    };

    RawProof::from_proof(
        &(proof.proof, program.vk()),
        proof.public_values.to_vec().into(),
    )
}
