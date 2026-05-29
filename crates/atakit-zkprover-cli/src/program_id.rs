use crate::utils::ProverArgs;
use atakit_zk_prover::Program;
use atakit_zk_types::ProgramId;
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
        
        if let Some(variant) = program.variant(prover.config().vm) {
            let program_id = variant.program_id();
            match program_id {
                ProgramId::Sp1 { vk_bytes } => println!("SP1 vk_hash: {vk_bytes}"),
                ProgramId::Risc0 { image_id } => println!("Risc0 image_id: {image_id}"),
            }
        }
        Ok(())
    }
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
