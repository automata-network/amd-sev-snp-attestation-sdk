use anyhow::anyhow;
use sp1_sdk::{network::builder::NetworkProverBuilder, ProverClient, SP1Stdin};

use crate::utils::block_on;

use super::ProgramSP1;
use crate::{RawProof, RawProofType};

pub(crate) fn gen_raw_proof<Input, Output>(
    program: &ProgramSP1<Input, Output>,
    stdin: SP1Stdin,
    raw_proof_type: RawProofType,
) -> anyhow::Result<RawProof> {
    let mut builder = ProverClient::builder().network();
    if let Some(private_key) = &program.config().private_key {
        builder = builder.private_key(private_key);
    }
    if let Some(rpc_url) = &program.config().rpc_url {
        builder = builder.rpc_url(rpc_url);
    }
    let prover = builder.build();

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

pub(crate) fn upload_image<Input, Output>(
    program: &ProgramSP1<Input, Output>,
) -> anyhow::Result<()> {
    let private_key = program
        .config()
        .private_key
        .as_ref()
        .ok_or_else(|| anyhow!("missing SP1_PRIVATE_KEY for SP1 upload"))?;

    block_on(async {
        let mut builder = NetworkProverBuilder::default().private_key(private_key);
        if let Some(api_url) = &program.config().rpc_url {
            builder = builder.rpc_url(api_url);
        }
        let prover = builder.build();
        prover.register_program(program.vk(), program.elf()).await?;
        Ok(())
    })
}
