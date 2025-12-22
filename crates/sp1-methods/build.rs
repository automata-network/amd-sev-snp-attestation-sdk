use sp1_build::{build_program_with_args, BuildArgs};
use std::path::Path;

fn main() {
    let elf_path = "./elf/sp1-verifier-elf";

    if Path::new(elf_path).exists() {
        println!(
            "cargo::warning=Skipping build for sp1-verifier (ELF exists at {})",
            elf_path
        );
        println!("cargo::rerun-if-changed={}", elf_path);
        return;
    }

    let use_docker = std::env::var("USE_DOCKER").is_ok();
    let workspace_directory = if use_docker {
        let manifest_dir =
            std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set");
        let workspace_root = std::path::Path::new(&manifest_dir)
            .parent()
            .and_then(|p| p.parent())
            .expect("Failed to find workspace root");
        Some(workspace_root.to_string_lossy().to_string())
    } else {
        None
    };

    build_program_with_args(
        "./sp1-verifier",
        BuildArgs {
            output_directory: Some("./elf".to_string()),
            elf_name: Some("sp1-verifier-elf".to_string()),
            docker: use_docker,
            workspace_directory,
            ..Default::default()
        },
    )
}
