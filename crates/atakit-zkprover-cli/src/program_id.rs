use std::path::PathBuf;

use crate::utils::ProverArgs;
use anyhow::{anyhow, bail};
use atakit_zk_prover::Program;
use atakit_zk_types::{ProgramId, RemoteProgramVariant};
use clap::Args;

#[derive(Args)]
pub struct ProgramIdCli {
    #[clap(flatten)]
    prover: ProverArgs,
}

impl ProgramIdCli {
    pub fn run(&self) -> anyhow::Result<()> {
        let prover = self.prover.new_prover()?;
        let program = Program::new::<program_verifier::Guest>()?;
        let mut selected_program_id = None;
        for variant in program.variants() {
            if variant.vm() != prover.config().vm {
                continue;
            }

            let program_id = variant.program_id();
            selected_program_id = Some(program_id.clone());
            match program_id {
                ProgramId::Sp1 { vk_hash } => println!("SP1 vk_hash: {vk_hash}"),
                ProgramId::Risc0 { image_id } => println!("Risc0 image_id: {image_id}"),
            }
        }

        // // Convert LE words to BE for display
        // let verify_proof_id_bytes = program_id.verify_proof_id.0;
        // let be_words: [u32; 8] = unsafe { std::mem::transmute(verify_proof_id_bytes) };
        // let be_converted: [u32; 8] = be_words.map(|word| word.to_be());
        // let be_bytes: [u8; 32] = unsafe { std::mem::transmute(be_converted) };
        // let be_b256 = B256::from(be_bytes);

        // println!("ProgramID (Offchain): {}", be_b256);
        Ok(())
    }
}

fn remote_program_variant_json(program_id: ProgramId) -> anyhow::Result<String> {
    let variant = match program_id {
        ProgramId::Sp1 { vk_hash } => RemoteProgramVariant::Sp1 { vk_hash },
        ProgramId::Risc0 { .. } => {
            bail!("RISC0 remote program JSON requires artifact_uri; use upload instead")
        }
    };

    Ok(serde_json::to_string_pretty(&variant)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::B256;
    use atakit_zk_types::RemoteProgramVariant;
    use clap::Parser;

    #[derive(Parser)]
    struct TestCli {
        #[clap(flatten)]
        program_id: ProgramIdCli,
    }

    #[test]
    fn accepts_out_path() {
        let cli = TestCli::try_parse_from([
            "test",
            "--vm",
            "sp1",
            "--backend",
            "network",
            "--out",
            "samples/sp1_remote_program.json",
        ])
        .unwrap();

        assert_eq!(
            cli.program_id.out.as_deref(),
            Some(std::path::Path::new("samples/sp1_remote_program.json"))
        );
    }

    #[test]
    fn encodes_sp1_remote_program_variant_json() {
        let json = remote_program_variant_json(ProgramId::Sp1 {
            vk_hash: B256::repeat_byte(1),
        })
        .unwrap();
        let variant: RemoteProgramVariant = serde_json::from_str(&json).unwrap();

        assert_eq!(
            variant,
            RemoteProgramVariant::Sp1 {
                vk_hash: B256::repeat_byte(1)
            }
        );
    }

    #[test]
    fn rejects_risc0_remote_program_variant_json_without_artifact_uri() {
        let error = remote_program_variant_json(ProgramId::Risc0 {
            image_id: B256::repeat_byte(2),
        })
        .unwrap_err();

        assert!(error.to_string().contains("artifact_uri"));
    }
}
