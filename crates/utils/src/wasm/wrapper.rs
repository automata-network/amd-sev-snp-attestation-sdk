//! Serializable wrapper types for WASM boundary.
//!
//! These types convert the alloy-sol-types generated structures into
//! frontend-friendly, JSON-serializable formats.

use serde::{Deserialize, Serialize};

use crate::{ProcessorType, VerificationResult, VerifierJournal};

/// Wrapper for VerifierJournal that can be serialized to/from JSON for WASM.
///
/// All byte arrays are hex-encoded strings for JavaScript compatibility.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifierJournalWrapper {
    /// Verification result as a string: "Success", "RootCertNotTrusted",
    /// "IntermediateCertsNotTrusted", or "InvalidTimestamp"
    pub result: String,

    /// Attestation timestamp (Unix epoch seconds)
    pub timestamp: u64,

    /// Processor model as a string: "Milan", "Genoa", "Bergamo", or "Siena"
    pub processor_model: String,

    /// Raw attestation report (1184 bytes), hex-encoded with "0x" prefix
    pub raw_report: String,

    /// Certificate hashes (bytes32[]), each hex-encoded with "0x" prefix
    pub certs: Vec<String>,

    /// Certificate serial numbers (uint160[]), each hex-encoded with "0x" prefix
    pub cert_serials: Vec<String>,

    /// Number of trusted certificate chain prefix elements
    pub trusted_certs_prefix_len: u8,
}

impl From<VerifierJournal> for VerifierJournalWrapper {
    fn from(journal: VerifierJournal) -> Self {
        let result = match journal.result {
            VerificationResult::Success => "Success",
            VerificationResult::RootCertNotTrusted => "RootCertNotTrusted",
            VerificationResult::IntermediateCertsNotTrusted => "IntermediateCertsNotTrusted",
            VerificationResult::InvalidTimestamp => "InvalidTimestamp",
            _ => "Unknown",
        }
        .to_string();

        let processor_model = match ProcessorType::try_from(journal.processorModel) {
            Ok(ProcessorType::Milan) => "Milan",
            Ok(ProcessorType::Genoa) => "Genoa",
            Ok(ProcessorType::Bergamo) => "Bergamo",
            Ok(ProcessorType::Siena) => "Siena",
            _ => "Unknown",
        }
        .to_string();

        let raw_report = format!("0x{}", hex::encode(&journal.rawReport));

        let certs = journal
            .certs
            .iter()
            .map(|c| format!("0x{}", hex::encode(c)))
            .collect();

        let cert_serials = journal
            .certSerials
            .iter()
            .map(|s| format!("0x{}", hex::encode(s.to_be_bytes::<20>())))
            .collect();

        Self {
            result,
            timestamp: journal.timestamp,
            processor_model,
            raw_report,
            certs,
            cert_serials,
            trusted_certs_prefix_len: journal.trustedCertsPrefixLen,
        }
    }
}

impl TryFrom<VerifierJournalWrapper> for VerifierJournal {
    type Error = anyhow::Error;

    fn try_from(wrapper: VerifierJournalWrapper) -> Result<Self, Self::Error> {
        use alloy_primitives::{FixedBytes, Uint};

        let result = match wrapper.result.as_str() {
            "Success" => VerificationResult::Success,
            "RootCertNotTrusted" => VerificationResult::RootCertNotTrusted,
            "IntermediateCertsNotTrusted" => VerificationResult::IntermediateCertsNotTrusted,
            "InvalidTimestamp" => VerificationResult::InvalidTimestamp,
            _ => anyhow::bail!("Unknown verification result: {}", wrapper.result),
        };

        let processor_model = match wrapper.processor_model.as_str() {
            "Milan" => ProcessorType::Milan as u8,
            "Genoa" => ProcessorType::Genoa as u8,
            "Bergamo" => ProcessorType::Bergamo as u8,
            "Siena" => ProcessorType::Siena as u8,
            _ => anyhow::bail!("Unknown processor model: {}", wrapper.processor_model),
        };

        let raw_report = hex::decode(wrapper.raw_report.trim_start_matches("0x"))
            .map_err(|e| anyhow::anyhow!("Failed to decode raw_report: {}", e))?;

        let certs: Result<Vec<FixedBytes<32>>, _> = wrapper
            .certs
            .iter()
            .map(|c| {
                let bytes = hex::decode(c.trim_start_matches("0x"))?;
                if bytes.len() != 32 {
                    anyhow::bail!("Invalid cert hash length: expected 32, got {}", bytes.len());
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                Ok(FixedBytes(arr))
            })
            .collect();
        let certs = certs?;

        let cert_serials: Result<Vec<Uint<160, 3>>, _> = wrapper
            .cert_serials
            .iter()
            .map(|s| {
                let bytes = hex::decode(s.trim_start_matches("0x"))?;
                if bytes.len() > 20 {
                    anyhow::bail!(
                        "Invalid cert serial length: expected <= 20, got {}",
                        bytes.len()
                    );
                }
                // Pad to 20 bytes if needed
                let mut padded = [0u8; 20];
                let start = 20 - bytes.len();
                padded[start..].copy_from_slice(&bytes);
                Ok(Uint::from_be_bytes(padded))
            })
            .collect();
        let cert_serials = cert_serials?;

        Ok(Self {
            result,
            timestamp: wrapper.timestamp,
            processorModel: processor_model,
            rawReport: raw_report.into(),
            certs,
            certSerials: cert_serials,
            trustedCertsPrefixLen: wrapper.trusted_certs_prefix_len,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roundtrip() {
        use alloy_primitives::{FixedBytes, Uint};

        let journal = VerifierJournal {
            result: VerificationResult::Success,
            timestamp: 1234567890,
            processorModel: ProcessorType::Genoa as u8,
            rawReport: vec![0u8; 1184].into(),
            certs: vec![FixedBytes([1u8; 32]), FixedBytes([2u8; 32])],
            certSerials: vec![Uint::from(12345u64), Uint::from(67890u64)],
            trustedCertsPrefixLen: 2,
        };

        let wrapper: VerifierJournalWrapper = journal.clone().into();
        let roundtrip: VerifierJournal = wrapper.try_into().expect("roundtrip failed");

        assert_eq!(journal.result, roundtrip.result);
        assert_eq!(journal.timestamp, roundtrip.timestamp);
        assert_eq!(journal.processorModel, roundtrip.processorModel);
        assert_eq!(journal.rawReport, roundtrip.rawReport);
        assert_eq!(journal.certs, roundtrip.certs);
        assert_eq!(journal.certSerials, roundtrip.certSerials);
        assert_eq!(journal.trustedCertsPrefixLen, roundtrip.trustedCertsPrefixLen);
    }
}
