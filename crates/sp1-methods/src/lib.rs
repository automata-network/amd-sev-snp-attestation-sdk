use lazy_static::lazy_static;
use sp1_sdk::{
    blocking::{Prover, ProverClient},
    Elf, ProvingKey, SP1ProvingKey, SP1VerifyingKey,
};

pub const SP1_VERIFIER_ELF: &[u8] = include_bytes!(".././elf/sp1-verifier-elf");

lazy_static! {
    pub static ref SP1_VERIFIER_VK: SP1VerifyingKey = vk(SP1_VERIFIER_ELF);
    pub static ref SP1_VERIFIER_PK: SP1ProvingKey = pk(SP1_VERIFIER_ELF);
}

fn vk(elf: &'static [u8]) -> SP1VerifyingKey {
    pk(elf).verifying_key().clone()
}

fn pk(elf: &'static [u8]) -> SP1ProvingKey {
    ProverClient::builder()
        .light()
        .build()
        .setup(Elf::Static(elf))
        .expect("failed to build SP1 verifier proving key")
}
