use alloy_primitives::Bytes;
use alloy_rpc_types::TransactionReceipt;
use amd_sev_snp_attestation_verifier::{
    stub::{VerifierInput, VerifierJournal, ZkCoProcessorType},
    AttestationReport,
};
use anyhow::{anyhow, bail, Context};
use lazy_static::lazy_static;
use x509_verifier_rust_crypto::CertChain;

use crate::{
    utils::block_on, OnchainProof, Program, ProgramId, ProverConfig, ProverSystemConfig, RawProof,
    RawProofType, RemoteProverConfig, SnpVerifierContract, KDS,
};

#[cfg(feature = "risc0")]
use risc0_methods::{self, RISC0_VERIFIER_ELF, RISC0_VERIFIER_ID};
#[cfg(feature = "sp1")]
use sp1_methods::{self, SP1_VERIFIER_ELF, SP1_VERIFIER_PK, SP1_VERIFIER_VK};
#[cfg(feature = "pico")]
use pico_methods::PICO_VERIFIER_ELF;

#[cfg(feature = "sp1")]
lazy_static! {
    pub static ref SP1_PROGRAM_VERIFIER: crate::ProgramSP1<ZkCoProcessorType, VerifierInput, VerifierJournal> =
        crate::ProgramSP1::new(ZkCoProcessorType::Succinct, SP1_VERIFIER_ELF, &SP1_VERIFIER_VK, &SP1_VERIFIER_PK);
}

#[cfg(feature = "risc0")]
lazy_static! {
    pub static ref RISC0_PROGRAM_VERIFIER: crate::ProgramRisc0<ZkCoProcessorType, VerifierInput, VerifierJournal> =
        crate::ProgramRisc0::new(ZkCoProcessorType::RiscZero, RISC0_VERIFIER_ELF, *RISC0_VERIFIER_ID);
}

#[cfg(feature = "pico")]
lazy_static! {
    pub static ref PICO_PROGRAM_VERIFIER: crate::ProgramPico<VerifierInput, VerifierJournal> =
        crate::ProgramPico::new(PICO_VERIFIER_ELF);
}

pub struct AmdSevSnpProver {
    kds: KDS,
    cfg: ProverConfig,
    // /// Optional smart contract for optimized certificate verification
    contract: Option<SnpVerifierContract>,
    /// Configuration for remote proving services
    remote_prover_config: Result<RemoteProverConfig, String>,
    /// ZK program for verifying individual attestation reports
    pub verifier: Box<
        dyn Program<ZkType = ZkCoProcessorType, Input = VerifierInput, Output = VerifierJournal>,
    >,
}

impl AmdSevSnpProver {
    pub fn new(cfg: ProverConfig, contract: Option<SnpVerifierContract>) -> Self {
        match &cfg.system {
            #[cfg(feature = "sp1")]
            ProverSystemConfig::Succinct(system_cfg) => {
                if let Some(api_url) = &system_cfg.rpc_url {
                    std::env::set_var("NETWORK_RPC_URL", api_url);
                }
                if let Some(api_key) = &system_cfg.private_key {
                    std::env::set_var("NETWORK_API_KEY", api_key);
                }
                AmdSevSnpProver {
                    kds: KDS::new(),
                    contract,
                    remote_prover_config: system_cfg
                        .clone()
                        .try_into()
                        .map_err(|err| format!("{:?}", err)),
                    cfg,
                    verifier: Box::new(SP1_PROGRAM_VERIFIER.clone()),
                }
            }
            #[cfg(feature = "risc0")]
            ProverSystemConfig::RiscZero(system_cfg) => {
                if let Some(rpc_url) = &system_cfg.rpc_url {
                    std::env::set_var("BOUNDLESS_RPC_URL", rpc_url);
                }
                if let Some(private_key) = &system_cfg.private_key {
                    std::env::set_var("BOUNDLESS_PRIVATE_KEY", private_key);
                }
                AmdSevSnpProver {
                    kds: KDS::new(),
                    contract,
                    remote_prover_config: system_cfg
                        .clone()
                        .try_into()
                        .map_err(|err| format!("{:?}", err)),
                    cfg,
                    verifier: Box::new(RISC0_PROGRAM_VERIFIER.clone()),
                }
            }
            #[cfg(feature = "pico")]
            ProverSystemConfig::Pico(_system_cfg) => {
                AmdSevSnpProver {
                    kds: KDS::new(),
                    contract,
                    remote_prover_config: Err("Remote prover not supported for Pico".to_string()),
                    cfg,
                    verifier: Box::new(PICO_PROGRAM_VERIFIER.clone()),
                }
            }
        }
    }

    /// Returns the zero-knowledge coprocessor type used by this prover.
    ///
    /// This method identifies which ZK proof system (RISC0 or SP1) the prover
    /// instance is configured to use. Both verifier and aggregator are same zktype.
    ///
    /// # Returns
    ///
    /// The ZK coprocessor type enumeration value
    pub fn get_zk_type(&self) -> ZkCoProcessorType {
        self.verifier.zktype()
    }

    /// Returns the program identifiers for both verifier and aggregator circuits.
    ///
    /// These identifiers are used by smart contracts and verifiers to ensure
    /// they are validating proofs from the correct ZK programs.
    ///
    /// # Returns
    ///
    /// A `ProgramId` struct containing:
    /// - `verifier_id`: The onchain representation of theprogram ID for verification
    /// - `verifier_proof_id`: The offchain representation of the program ID for proof generation
    pub fn get_program_id(&self) -> ProgramId {
        ProgramId {
            verifier_id: self.verifier.program_id(),
            verify_proof_id: self.verifier.verify_proof_id(),
        }
    }

    /// Converts a raw ZK proof into a format suitable for onchain verification.
    ///
    /// This method transforms the internal proof representation into bytes
    /// that can be submitted to smart contracts for on-chain verification.
    /// The exact encoding depends on the underlying ZK system (RISC0 or SP1).
    ///
    /// # Arguments
    ///
    /// * `proof` - The raw proof to be encoded
    ///
    pub fn encode_proof_for_onchain(&self, proof: &RawProof) -> anyhow::Result<Bytes> {
        self.verifier.onchain_proof(proof)
    }

    /// Uploads both verifier and aggregator program images to the remote proving service.
    ///
    /// This method deploys the ZK programs to remote infrastructure (like Bonsai for RISC0
    /// or SP1 Network for SP1) to enable faster cloud-based proof generation.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use amd_sev_snp_attestation_prover::{AmdSevSnpProver, ProverConfig};
    ///
    /// fn main() -> anyhow::Result<()> {
    ///     let prover = AmdSevSnpProver::new(ProverConfig::risc0(), None);
    ///     let program_id = prover.upload_program_images()?;
    ///     println!("Programs uploaded successfully: {:?}", program_id);
    ///     Ok(())
    /// }
    /// ```
    pub fn upload_program_images(&self) -> anyhow::Result<ProgramId> {
        let cfg = match &self.remote_prover_config {
            Ok(cfg) => cfg,
            Err(err) => bail!("{}", err),
        };
        self.verifier.upload_image(&cfg)?;
        Ok(self.get_program_id())
    }

    /// Generates a zero-knowledge proof for a single AWS Nitro Enclave attestation report.
    ///
    /// This is the primary method for proving individual attestation reports. It handles
    /// the complete workflow from parsing the raw report to generating a blockchain-ready proof.
    ///
    /// # Arguments
    ///
    /// * `report_bytes` - Raw attestation report bytes from AWS Nitro Enclave
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use amd_sev_snp_attestation_prover::{AmdSevSnpProver, ProverConfig};
    ///
    /// fn main() -> anyhow::Result<()> {
    ///     let prover = AmdSevSnpProver::new(ProverConfig::risc0(), None);
    ///     let report_bytes = std::fs::read("samples/attestation_1.report")?;
    ///     let proof = prover.prove_attestation_report(report_bytes)?;
    ///
    ///     // Submit to blockchain or save for later use
    ///     std::fs::write("proof.json", proof.encode_json()?)?;
    ///     Ok(())
    /// }
    /// ```
    pub fn prove_attestation_report(
        &self,
        timestamp: u64,
        raw_report: Bytes,
        vek_certs: Option<Vec<Bytes>>,
    ) -> anyhow::Result<OnchainProof> {
        let input = self.prepare_verifier_input(timestamp, raw_report, vek_certs)?;
        let proof = self
            .verifier
            .gen_proof(&input, RawProofType::Groth16, None)?;
        Ok(self.create_onchain_proof(proof)?)
    }

    pub fn prepare_verifier_input(
        &self,
        timestamp: u64,
        raw_report: Bytes,
        vek_certs: Option<Vec<Bytes>>,
    ) -> anyhow::Result<VerifierInput> {
        let report = AttestationReport::from_bytes(&raw_report)?;
        let vek_certs = match vek_certs {
            Some(vek_certs) => vek_certs,
            None => self.kds.fetch_report_cert_chain(&report)?,
        };
        let cert_chain = CertChain::parse_rev(&vek_certs)?;
        cert_chain.verify_chain()?;
        cert_chain.check_valid(timestamp)?;
        let mut trusted_certs_prefix_len = 2;
        if let Some(contract) = &self.contract {
            let program_id = block_on(contract.program_id(self.verifier.zktype()))?;
            let verify_result = self.get_program_id().verify(&program_id).with_context(|| {
                format!("Failed to verify zkconfig for {:?}", self.verifier.zktype())
            });
            if let Err(verify_err) = verify_result {
                if !self.cfg.skip_contract_program_id_check {
                    bail!(
                            "Program ID verification failed: {:?}. Set SKIP_CONTRACT_PROGRAM_ID_CHECK=true to ignore this check.",
                            verify_err
                        );
                } else {
                    tracing::warn!("Program ID verification failed: {:?}.", verify_err);
                }
            }
            let processor_model = report.get_cpu_codename()?;
            let result = block_on(contract.batch_query_cert_cache(
                vec![processor_model],
                vec![cert_chain.digest().to_vec()],
            ))?;
            trusted_certs_prefix_len = result[0];
        } else {
            tracing::warn!("Contract not provided, may lead to attestation failures and increased costs. Not recommended for production.");
        }
        Ok(VerifierInput {
            timestamp,
            trustedCertsPrefixLen: trusted_certs_prefix_len,
            rawReport: raw_report,
            vekDerChain: cert_chain.to_ders(),
        })
    }

    /// Builds a complete proof result with all metadata for blockchain submission.
    ///
    /// This method constructs an `OnchainProof` structure that packages the raw ZK proof
    /// along with all necessary metadata required for on-chain verification. The resulting
    /// proof package is ready for submission to smart contracts.
    ///
    /// # Arguments
    ///
    /// * `raw_proof` - The raw zero-knowledge proof generated by the ZK program
    /// * `proof_type` - The type of proof (Verifier for single attestations, Aggregator for batch)
    ///
    /// # Proof Package Contents
    ///
    /// The resulting `OnchainProof` contains:
    /// - Proof bytes suitable for smart contract verification
    /// - Program identifiers for verification logic validation
    /// - Proof type metadata for correct contract method selection
    /// - ZK system information (RISC0 or SP1)
    /// - Serialization helpers for JSON export
    ///
    /// # Usage
    ///
    /// This method is typically called internally by `prove_attestation_report()`
    /// and `prove_multiple_reports()`. Direct usage is for advanced scenarios
    /// where custom proof processing is required.
    /// ```
    pub fn create_onchain_proof(&self, raw_proof: RawProof) -> anyhow::Result<OnchainProof> {
        Ok(OnchainProof::new_from_program(
            &*self.verifier,
            self.get_program_id(),
            raw_proof,
        )?)
    }

    /// Verifies a zero-knowledge proof on the Ethereum blockchain via smart contract.
    ///
    /// This method submits a previously generated ZK proof to the deployed Nitro Enclave
    /// Verifier smart contract for on-chain verification.
    ///
    /// # Arguments
    ///
    /// * `proof` - The result generated by `prove_attestation_report()` or `prove_multiple_reports()`
    ///
    /// # Prerequisites
    ///
    /// This method requires that the prover was initialized with a valid smart contract:
    /// - The contract must be deployed and accessible via the configured RPC endpoint
    /// - The contract must support the proof type being verified (RISC0 or SP1)
    /// - The program identifiers in the proof must match those registered in the contract
    ///
    pub fn verify_on_chain(&self, proof: &OnchainProof) -> anyhow::Result<VerifierJournal> {
        let contract = self
            .contract
            .as_ref()
            .ok_or_else(|| anyhow!("verify on chain requires contract info"))?;
        let result = block_on(contract.verify_proof(proof))
            .map_err(|err| anyhow!("Failed to verify proof on chain: {}", err))?;
        Ok(result)
    }

    pub fn submit_on_chain(&self, proof: &OnchainProof) -> anyhow::Result<TransactionReceipt> {
        let contract = self
            .contract
            .as_ref()
            .ok_or_else(|| anyhow!("submit on chain requires contract info"))?;
        let receipt = block_on(contract.submit_proof(proof))
            .map_err(|err| anyhow!("Failed to submit proof on chain: {}", err))?;
        Ok(receipt)
    }
}
