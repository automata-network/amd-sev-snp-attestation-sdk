use std::{
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use alloy_primitives::{Bytes, B256};
use anyhow::{anyhow, bail};
use atakit_zk_prover::RemoteProgram;
use atakit_zk_types::{ProgramId, ProofKind, RemoteProgramVariant, ZkVmSelection};
use clap::Args;
use contract_stub::ZkCoProcessorType;
use program_verifier::VerifierInput;
use serde::Serialize;

use crate::utils::{AttestationReportWithVekCertChain, ContractArgs, ProverArgs, VmArg};

/// Arguments for proving an already published remote ZK program.
#[derive(Args)]
pub struct ProveRemoteProgramCli {
    /// Path to a RemoteProgramVariant JSON file
    #[clap(long)]
    program_variant: PathBuf,

    /// Path to an AMD SEV-SNP attestation report file
    #[clap(long)]
    report: PathBuf,

    /// Zero-knowledge proof system configuration
    #[clap(flatten)]
    prover: ProverArgs,

    /// Smart contract configuration for on-chain verification
    #[clap(flatten)]
    contract: ContractArgs,

    /// Verify the generated proof by calling verifyAndAttestWithZKProof
    #[clap(long)]
    verify_on_chain: bool,
}

#[derive(Serialize, Debug, Clone)]
struct OnchainProofOutput {
    vm: ZkVmSelection,
    program_id: B256,
    proof: Bytes,
    journal: Bytes,
}

impl ProveRemoteProgramCli {
    pub async fn run(&self) -> anyhow::Result<()> {
        let remote_variant = read_remote_program_variant(&self.program_variant)?;
        let vm = self.prover.vm.selection();
        if remote_variant.vm() != vm {
            bail!(
                "Remote program variant VM {:?} does not match --vm {:?}",
                remote_variant.vm(),
                vm
            );
        }

        let input = verifier_input_from_report(&self.report)?;
        let prover = self.prover.new_prover()?;
        let remote_program = RemoteProgram::from(remote_variant);
        let result = prover
            .prove_remote_program(
                &remote_program,
                Bytes::from(input.encode()),
                ProofKind::Groth16,
            )
            .await?;

        let proof = onchain_proof_output(result.artifact)?;
        println!("{}", serde_json::to_string_pretty(&proof)?);

        if self.verify_on_chain {
            let contract = self.contract.stub()?.ok_or_else(|| {
                anyhow!(
                    "No contract specified. Use --contract and --rpc-url to specify the contract."
                )
            })?;
            let result = contract
                .call_verify(zk_type(self.prover.vm), proof.proof, proof.journal)
                .await?;
            dbg!(result);
        }

        Ok(())
    }
}

fn read_remote_program_variant(path: &PathBuf) -> anyhow::Result<RemoteProgramVariant> {
    Ok(serde_json::from_slice(&std::fs::read(path)?)?)
}

fn verifier_input_from_report(path: &PathBuf) -> anyhow::Result<VerifierInput> {
    let report_with_cert_chain = AttestationReportWithVekCertChain::decode(&std::fs::read(path)?)?;
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let mut vek_certs = report_with_cert_chain.vek_certs.unwrap_or_default();
    vek_certs.reverse();

    Ok(VerifierInput {
        timestamp,
        rawReport: report_with_cert_chain.report,
        vekDerChain: vek_certs,
    })
}

fn onchain_proof_output(
    artifact: atakit_zk_prover::ProofArtifact,
) -> anyhow::Result<OnchainProofOutput> {
    let vm = artifact.vm();
    let program_id = program_id_b256(artifact.program_id()?);
    let proof = artifact.onchain_proof_bytes()?.0;
    let journal = artifact.journal();

    Ok(OnchainProofOutput {
        vm,
        program_id,
        proof,
        journal,
    })
}

fn program_id_b256(program_id: ProgramId) -> B256 {
    match program_id {
        ProgramId::Sp1 { vk_bytes } => vk_bytes,
        ProgramId::Risc0 { image_id } => image_id,
    }
}

fn zk_type(vm: VmArg) -> ZkCoProcessorType {
    match vm {
        VmArg::Risc0 => ZkCoProcessorType::RiscZero,
        VmArg::Sp1 => ZkCoProcessorType::Succinct,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser)]
    struct TestCli {
        #[clap(flatten)]
        prove_remote_program: ProveRemoteProgramCli,
    }

    fn base_args() -> Vec<&'static str> {
        vec![
            "test",
            "--vm",
            "sp1",
            "--backend",
            "network",
            "--program-variant",
            "samples/sp1_remote_program.json",
            "--report",
            "samples/registration_azure_snp.json",
        ]
    }

    #[test]
    fn accepts_remote_program_inputs() {
        let cli = TestCli::try_parse_from(base_args()).unwrap();

        assert_eq!(
            cli.prove_remote_program.program_variant,
            std::path::PathBuf::from("samples/sp1_remote_program.json")
        );
        assert_eq!(
            cli.prove_remote_program.report,
            std::path::PathBuf::from("samples/registration_azure_snp.json")
        );
    }

    #[test]
    fn rejects_out_flag() {
        let mut args = base_args();
        args.extend(["--out", "proof.json"]);

        assert!(TestCli::try_parse_from(args).is_err());
    }
}
