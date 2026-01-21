//! AMD SEV-SNP Utils
//!
//! Utility crate providing WASM bindings for frontend integration.
//! Specifically designed for parsing and encoding the VerifierJournal data structure.

#[cfg(feature = "wasm")]
mod wasm;

// Re-export core types from verifier crate
pub use amd_sev_snp_attestation_verifier::stub::{
    ProcessorType, VerificationResult, VerifierInput, VerifierJournal, ZkCoProcessorType,
};

#[cfg(feature = "wasm")]
pub use wasm::*;
