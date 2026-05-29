use std::str::FromStr;

use alloy_primitives::{FixedBytes, Uint};
use alloy_sol_types::SolValue;
use anyhow::bail;
use tiny_keccak::{Hasher, Keccak};

alloy_sol_types::sol! {
    #[derive(Debug)]
    enum ProcessorType {
        // 7003 series AMD EPYC Processor
        Milan,
        // 9004 series AMD EPYC Processor
        Genoa,
        // 97x4 series AMD EPYC Processor
        Bergamo,
        // 8004 series AMD EPYC Processor
        Siena
    }

    #[derive(Debug)]
    enum VerificationResult {
        // Attestation successfully verified
        Success,
        // Root certificate is not in the trusted set
        RootCertNotTrusted,
        // Attestation timestamp is outside acceptable range
        InvalidTimestamp
    }

    #[derive(Debug)]
    struct VerifierInput {
        uint64 timestamp;
        bytes rawReport;
        bytes[] vekDerChain;
    }

    #[derive(Debug)]
    struct VerifierJournal {
        VerificationResult result;
        uint64 timestamp;
        uint8 processorModel;
        bytes32 reportHash;
        bytes32[] certs;
        uint160[] certSerials;
    }

    #[derive(Debug, serde::Serialize, serde::Deserialize)]
    enum ZkCoProcessorType {
        None,
        RiscZero,
        Succinct,
        Pico
    }
}

impl ProcessorType {
    pub fn to_str(&self) -> anyhow::Result<&'static str> {
        Ok(match self {
            Self::Milan => "Milan",
            Self::Genoa => "Genoa",
            Self::Bergamo => "Bergamo",
            Self::Siena => "Siena",
            _ => bail!("Unknown Processor Model"),
        })
    }
}

impl FromStr for ProcessorType {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "Milan" => Ok(ProcessorType::Milan),
            "Genoa" => Ok(ProcessorType::Genoa),
            "Bergamo" => Ok(ProcessorType::Bergamo),
            "Siena" => Ok(ProcessorType::Siena),
            _ => Err(anyhow::anyhow!("Unknown Processor Model: {}", s)),
        }
    }
}

impl VerifierInput {
    pub fn encode(&self) -> Vec<u8> {
        self.abi_encode()
    }

    pub fn decode(input: &[u8]) -> anyhow::Result<Self> {
        Self::abi_decode(input)
            .map_err(|e| anyhow::anyhow!("Failed to decode VerifierInput: {}", e))
    }
}

impl VerifierJournal {
    /// Encode the journal as raw bytes concatenation (big-endian for multi-byte values):
    ///   u8 result | u64 timestamp | u8 processorModel | u32 certSize |
    ///   bytes32[certSize] certs | u160[certSize] certSerials | bytes32 reportHash
    pub fn encode(&self) -> Vec<u8> {
        let cert_size = self.certs.len() as u32;
        let total_len = 1 + 8 + 1 + 4 + (32 * cert_size as usize) + (20 * cert_size as usize) + 32;
        let mut buf = Vec::with_capacity(total_len);

        buf.push(self.result as u8);
        buf.extend_from_slice(&self.timestamp.to_be_bytes());
        buf.push(self.processorModel);
        buf.extend_from_slice(&cert_size.to_be_bytes());

        for cert in &self.certs {
            buf.extend_from_slice(cert.as_slice());
        }

        for serial in &self.certSerials {
            buf.extend_from_slice(&serial.to_be_bytes::<20>());
        }

        buf.extend_from_slice(self.reportHash.as_slice());

        buf
    }

    /// Decode the journal from raw bytes concatenation (inverse of encode)
    pub fn decode(input: &[u8]) -> anyhow::Result<Self> {
        let mut offset = 0;

        if input.len() < 1 + 8 + 1 + 4 {
            bail!(
                "Journal too short: need at least 14 bytes, got {}",
                input.len()
            );
        }

        let result_byte = input[offset];
        let result = match result_byte {
            0 => VerificationResult::Success,
            1 => VerificationResult::RootCertNotTrusted,
            2 => VerificationResult::InvalidTimestamp,
            _ => bail!("Unknown VerificationResult: {}", result_byte),
        };
        offset += 1;

        let timestamp = u64::from_be_bytes(input[offset..offset + 8].try_into()?);
        offset += 8;

        let processor_model = input[offset];
        offset += 1;

        let cert_size = u32::from_be_bytes(input[offset..offset + 4].try_into()?) as usize;
        offset += 4;

        let needed = offset + (32 * cert_size) + (20 * cert_size) + 32;
        if input.len() < needed {
            bail!(
                "Journal too short: need {} bytes for {} certs, got {}",
                needed,
                cert_size,
                input.len()
            );
        }

        let mut certs = Vec::with_capacity(cert_size);
        for _ in 0..cert_size {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&input[offset..offset + 32]);
            certs.push(FixedBytes(arr));
            offset += 32;
        }

        let mut cert_serials = Vec::with_capacity(cert_size);
        for _ in 0..cert_size {
            let mut arr = [0u8; 20];
            arr.copy_from_slice(&input[offset..offset + 20]);
            cert_serials.push(Uint::from_be_bytes(arr));
            offset += 20;
        }

        let mut report_hash_arr = [0u8; 32];
        report_hash_arr.copy_from_slice(&input[offset..offset + 32]);
        let report_hash = FixedBytes(report_hash_arr);

        Ok(Self {
            result,
            timestamp,
            processorModel: processor_model,
            reportHash: report_hash,
            certs,
            certSerials: cert_serials,
        })
    }
}

/// Compute keccak256 hash of the given data
pub fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak::v256();
    let mut output = [0u8; 32];
    hasher.update(data);
    hasher.finalize(&mut output);
    output
}
