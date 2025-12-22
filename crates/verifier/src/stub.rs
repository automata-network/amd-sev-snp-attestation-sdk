use std::str::FromStr;

use alloy_sol_types::SolValue;
use anyhow::bail;
use serde::{Deserialize, Serialize};

alloy_sol_types::sol! {
    #[sol(docs, extra_derives(Debug, Serialize, Deserialize))]
    "../../contracts/src/types/SevSnpTypes.sol"
}

alloy_sol_types::sol! {
    #[sol(docs, extra_derives(Debug, Serialize, Deserialize))]
    "../../contracts/src/interfaces/ISnpAttestation.sol"
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
    pub fn encode(&self) -> Vec<u8> {
        self.abi_encode()
    }

    pub fn decode(input: &[u8]) -> anyhow::Result<Self> {
        Self::abi_decode(input)
            .map_err(|e| anyhow::anyhow!("Failed to decode VerifierJournal: {}", e))
    }
}
