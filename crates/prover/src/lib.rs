mod program;
pub use program::*;
mod prover;
pub use prover::*;
mod prover_types;
pub mod utils;
pub use prover_types::*;
mod kds;
pub use kds::*;
mod contract;
pub use contract::*;

#[cfg(feature = "sp1")]
pub mod program_sp1;
#[cfg(feature = "sp1")]
pub use program_sp1::{ProgramSP1, SP1ProverConfig, SP1ProvingStrategy};

#[cfg(feature = "risc0")]
pub mod program_risc0;
#[cfg(feature = "risc0")]
pub use program_risc0::{
    BoundlessProofType, ProgramRisc0, RiscZeroProverConfig, RiscZeroProvingStrategy,
};

#[cfg(feature = "pico")]
pub mod program_pico;
#[cfg(feature = "pico")]
pub use program_pico::{
    MarketplaceConfig, PicoProverConfig, PicoProvingStrategy, ProgramPico,
};

pub fn set_prover_dev_mode(_dev_mode: bool) {
    #[cfg(feature = "sp1")]
    if _dev_mode {
        std::env::set_var("SP1_PROVER", "mock");
    } else {
        std::env::set_var("SP1_PROVER", "network");
    }

    #[cfg(feature = "risc0")]
    if _dev_mode {
        std::env::set_var("RISC0_STRATEGY", "dev");
    } else {
        std::env::set_var("RISC0_STRATEGY", "boundless");
    }

    #[cfg(feature = "pico")]
    if _dev_mode {
        std::env::set_var("PICO_DEV_MODE", "1");
        std::env::set_var("PICO_STRATEGY", "dev");
    } else {
        std::env::set_var("PICO_DEV_MODE", "0");
        std::env::set_var("PICO_STRATEGY", "marketplace");
    }
}
