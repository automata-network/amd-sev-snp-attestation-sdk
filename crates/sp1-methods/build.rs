use sp1_build::{build_program_with_args, BuildArgs};

fn main() {
    build_program_with_args(
        "./sp1-verifier",
        BuildArgs {
            output_directory: Some("./elf".to_string()),
            elf_name: Some("nitro-sp1-guest-program-elf".to_string()),
            docker: std::env::var("USE_DOCKER").is_ok(),
            ..Default::default()
        },
    )
}