use lazy_static::lazy_static;
use sp1_sdk::{EnvProver, SP1ProvingKey, SP1VerifyingKey};

pub const SP1_VERIFIER_ELF: &[u8] = include_bytes!(".././elf/sp1-verifier-elf");

lazy_static! {
    pub static ref ENV_PROVER: EnvProver = EnvProver::new();
    pub static ref SP1_VERIFIER_VK: SP1VerifyingKey = vk(SP1_VERIFIER_ELF);
    pub static ref SP1_VERIFIER_PK: SP1ProvingKey = pk(SP1_VERIFIER_ELF);
}

fn vk(elf: &[u8]) -> SP1VerifyingKey {
    let (_, vk) = ENV_PROVER.setup(elf);
    vk
}

fn pk(elf: &[u8]) -> SP1ProvingKey {
    let (pk, _) = ENV_PROVER.setup(elf);
    pk
}
