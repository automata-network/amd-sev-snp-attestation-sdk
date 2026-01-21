//! WASM bindings for AMD SEV-SNP attestation utilities.
//!
//! Provides functions for parsing and encoding VerifierJournal data structures
//! for frontend integration.

mod wrapper;

pub use wrapper::VerifierJournalWrapper;

use wasm_bindgen::prelude::*;

use crate::VerifierJournal;

/// Parse ABI-encoded VerifierJournal bytes into a JSON-serializable object.
///
/// # Arguments
/// * `bytes` - ABI-encoded VerifierJournal bytes
///
/// # Returns
/// A JavaScript object representing the parsed VerifierJournal with fields:
/// - `result`: String ("Success", "RootCertNotTrusted", "IntermediateCertsNotTrusted", "InvalidTimestamp")
/// - `timestamp`: Number (Unix epoch seconds)
/// - `processorModel`: String ("Milan", "Genoa", "Bergamo", "Siena")
/// - `rawReport`: String (hex-encoded with "0x" prefix)
/// - `certs`: Array of Strings (hex-encoded bytes32 values)
/// - `certSerials`: Array of Strings (hex-encoded uint160 values)
/// - `trustedCertsPrefixLen`: Number
#[wasm_bindgen]
pub fn parse_verified_journal(bytes: &[u8]) -> JsValue {
    let journal = VerifierJournal::decode(bytes).expect("Failed to decode VerifierJournal");
    let wrapper: VerifierJournalWrapper = journal.into();
    serde_wasm_bindgen::to_value(&wrapper).expect("Failed to serialize to JsValue")
}

/// Encode a VerifierJournal object to ABI-encoded bytes.
///
/// # Arguments
/// * `journal` - A JavaScript object with the VerifierJournal structure (see parse_verified_journal for format)
///
/// # Returns
/// ABI-encoded bytes as a Uint8Array
#[wasm_bindgen]
pub fn encode_verified_journal(journal: JsValue) -> Vec<u8> {
    let wrapper: VerifierJournalWrapper =
        serde_wasm_bindgen::from_value(journal).expect("Failed to deserialize from JsValue");
    let journal: VerifierJournal = wrapper.try_into().expect("Failed to convert to VerifierJournal");
    journal.encode()
}
