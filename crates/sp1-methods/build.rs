use sp1_build::{build_program_with_args, BuildArgs};
use std::path::Path;

fn main() {
    println!("cargo::rerun-if-env-changed=FORCE_BUILD");

    let force_build = std::env::var("FORCE_BUILD")
        .map(|v| matches!(v.to_lowercase().as_str(), "1" | "true"))
        .unwrap_or(false);

    let elf_path = "./elf/sp1-verifier-elf";

    if force_build && Path::new(elf_path).exists() {
        println!(
            "cargo::warning=FORCE_BUILD set, removing existing ELF at {}",
            elf_path
        );
        std::fs::remove_file(elf_path).expect("Failed to remove existing ELF");
    }

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
        let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set");
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
