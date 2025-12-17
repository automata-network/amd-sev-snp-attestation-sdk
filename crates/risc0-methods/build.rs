use risc0_build::{embed_methods_with_options, DockerOptionsBuilder, GuestOptionsBuilder};
use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::PathBuf;

const RISC0_VERIFIER: &str = "risc0-verifier";

fn main() {
    let manifest_dir = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let out_dir = PathBuf::from(std::env::var_os("OUT_DIR").unwrap());
    let elf_dir = manifest_dir.join("elf");
    let elf_path = elf_dir.join(format!("{}-elf", RISC0_VERIFIER));

    let final_elf_path = if elf_path.exists() {
        println!(
            "cargo::warning=Skipping build for {} (ELF exists at {:?})",
            RISC0_VERIFIER, elf_path
        );
        elf_path
    } else {
        // Build the guest program
        let use_docker = std::env::var("USE_DOCKER").is_ok();
        let mut builder = GuestOptionsBuilder::default();
        if use_docker {
            let docker_options = DockerOptionsBuilder::default()
                .root_dir(manifest_dir.join("../../"))
                .build()
                .unwrap();
            builder.use_docker(docker_options);
        }
        let guest_options = builder.build().unwrap();
        embed_methods_with_options(HashMap::from([(RISC0_VERIFIER, guest_options)]));

        // Copy ELF to ./elf/ for future builds
        fs::create_dir_all(&elf_dir).unwrap();
        let profile = if use_docker { "docker" } else { "release" };
        let target_base = manifest_dir.join("../../target");
        let src = target_base.join(format!(
            "riscv-guest/risc0-methods/{}/riscv32im-risc0-zkvm-elf/{}/{}.bin",
            RISC0_VERIFIER, profile, RISC0_VERIFIER
        ));
        println!("cargo::warning=Copying {:?} to {:?}", src, elf_path);
        fs::copy(&src, &elf_path)
            .unwrap_or_else(|e| panic!("Failed to copy {:?} to {:?}: {}", src, elf_path, e));
        elf_path
    };

    // Generate methods.rs with include_bytes!
    let methods_path = out_dir.join("methods.rs");
    let mut file = fs::File::create(&methods_path).unwrap();
    writeln!(
        file,
        r#"pub const RISC0_VERIFIER_ELF: &[u8] = include_bytes!({:?});"#,
        final_elf_path
    )
    .unwrap();
    println!("cargo::rerun-if-changed={}", final_elf_path.display());
}
