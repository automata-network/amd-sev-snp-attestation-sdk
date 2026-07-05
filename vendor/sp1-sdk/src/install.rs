//! # SP1 Install
//!
//! A library for installing the SP1 circuit artifacts.

pub use sp1_prover::build::{
    download_file, install_circuit_artifacts, try_build_groth16_artifacts_dir,
    try_build_plonk_artifacts_dir, try_install_circuit_artifacts, CIRCUIT_ARTIFACTS_URL_BASE,
};
