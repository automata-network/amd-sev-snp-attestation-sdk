use std::{
    env, fs,
    path::{Path, PathBuf},
    process::Command,
};

const PICO_VERIFIER: &str = "pico-verifier";

fn main() {
    build_if_missing(PICO_VERIFIER);
}

fn build_if_missing(program_name: &str) {
    let elf_path = format!("{}/elf", program_name);
    let elf_target_path = format!("{}/riscv32im-pico-zkvm-elf", elf_path);

    // Re-run build script if FORCE_BUILD changes
    println!("cargo::rerun-if-env-changed=FORCE_BUILD");
    let force_build = std::env::var("FORCE_BUILD")
        .map(|v| v.eq_ignore_ascii_case("true") || v == "1")
        .unwrap_or(false);

    if force_build {
        let path = Path::new(&elf_target_path);
        if path.exists() {
            println!(
                "cargo::warning=FORCE_BUILD set, removing existing ELF: {}",
                elf_target_path
            );
            std::fs::remove_file(path).unwrap();
        }
    }

    if Path::new(&elf_target_path).exists() {
        println!(
            "cargo::warning=Skipping build for {} (ELF exists at {})",
            program_name, elf_path
        );
        return;
    }

    build(program_name, Path::new(&elf_path));
}

fn build(program_name: &str, elf_path: &Path) {
    println!("cargo::warning=Building Pico guest for {}", program_name);

    // Build directly into the final output directory
    fs::create_dir_all(elf_path).expect("Failed to create output directory");

    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let program_dir = manifest_dir.join(program_name);

    let status = Command::new("cargo")
        .args(["pico", "build"])
        .current_dir(&program_dir)
        .status()
        .expect("Failed to execute 'cargo pico build'. Is cargo-pico installed?");

    if !status.success() {
        panic!(
            "cargo pico build failed with exit code: {:?}",
            status.code()
        );
    }

    let built_elf = elf_path.join("riscv32im-pico-zkvm-elf");
    if !built_elf.exists() {
        panic!("Expected built ELF not found at {}", built_elf.display());
    }

    println!(
        "cargo::warning=Built Pico guest ELF at {}",
        built_elf.display()
    );

    // Dependency tracking
    println!("cargo::rerun-if-changed=./{}/src/main.rs", program_name);
    println!("cargo::rerun-if-changed=./{}/Cargo.toml", program_name);
}
