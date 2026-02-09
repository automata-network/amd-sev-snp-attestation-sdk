//! WASM bindings for AMD SEV-SNP attestation utilities.
//!
//! Provides functions for parsing and encoding VerifierJournal data structures
//! for frontend integration.

mod wrapper;

pub use wrapper::VerifierJournalWrapper;

use wasm_bindgen::prelude::*;

use crate::VerifierJournal;

/// Parse raw bytes-encoded VerifierJournal into a JSON-serializable object.
///
/// # Arguments
/// * `bytes` - Raw bytes-encoded VerifierJournal
///
/// # Returns
/// A JavaScript object representing the parsed VerifierJournal with fields:
/// - `result`: String ("Success", "RootCertNotTrusted", "InvalidTimestamp")
/// - `timestamp`: Number (Unix epoch seconds)
/// - `processorModel`: String ("Milan", "Genoa", "Bergamo", "Siena")
/// - `reportHash`: String (hex-encoded bytes32 with "0x" prefix)
/// - `certs`: Array of Strings (hex-encoded bytes32 values)
/// - `certSerials`: Array of Strings (hex-encoded uint160 values)
#[wasm_bindgen]
pub fn parse_verified_journal(bytes: &[u8]) -> JsValue {
    let journal = VerifierJournal::decode(bytes).expect("Failed to decode VerifierJournal");
    let wrapper: VerifierJournalWrapper = journal.into();
    serde_wasm_bindgen::to_value(&wrapper).expect("Failed to serialize to JsValue")
}

/// Encode a VerifierJournal object to raw bytes.
///
/// # Arguments
/// * `journal` - A JavaScript object with the VerifierJournal structure (see parse_verified_journal for format)
///
/// # Returns
/// Raw bytes-encoded journal as a Uint8Array
#[wasm_bindgen]
pub fn encode_verified_journal(journal: JsValue) -> Vec<u8> {
    let wrapper: VerifierJournalWrapper =
        serde_wasm_bindgen::from_value(journal).expect("Failed to deserialize from JsValue");
    let journal: VerifierJournal = wrapper.try_into().expect("Failed to convert to VerifierJournal");
    journal.encode()
}
