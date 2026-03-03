use alloy_primitives::Bytes;
use alloy_rpc_types::TransactionReceipt;
use amd_sev_snp_attestation_verifier::{
    stub::{VerifierInput, VerifierJournal, ZkCoProcessorType},
    AttestationReport,
};
use anyhow::{anyhow, bail, Context};
use x509_verifier_rust_crypto::CertChain;

use crate::{
    utils::block_on, OnchainProof, Program, ProgramId, ProverConfig, ProverSystemConfig, RawProof,
    RawProofType, SnpVerifierContract, KDS,
};

#[cfg(feature = "pico")]
use crate::program_pico::PICO_PROGRAM_VERIFIER;
#[cfg(feature = "risc0")]
use crate::program_risc0::RISC0_PROGRAM_VERIFIER;
#[cfg(feature = "sp1")]
use crate::program_sp1::SP1_PROGRAM_VERIFIER;

pub struct AmdSevSnpProver {
    kds: KDS,
    cfg: ProverConfig,
    contract: Option<SnpVerifierContract>,
    /// ZK program for verifying individual attestation reports.
    pub verifier: Box<
        dyn Program<ZkType = ZkCoProcessorType, Input = VerifierInput, Output = VerifierJournal>,
    >,
}

impl AmdSevSnpProver {
    pub fn new(cfg: ProverConfig, contract: Option<SnpVerifierContract>) -> Self {
        let prover_system = cfg.system.clone();
        match prover_system {
            #[cfg(feature = "sp1")]
            ProverSystemConfig::Succinct(system_cfg) => AmdSevSnpProver {
                kds: KDS::new(),
                contract,
                cfg,
                verifier: Box::new(SP1_PROGRAM_VERIFIER.with_config(system_cfg)),
            },
            #[cfg(feature = "risc0")]
            ProverSystemConfig::RiscZero(system_cfg) => AmdSevSnpProver {
                kds: KDS::new(),
                contract,
                cfg,
                verifier: Box::new(RISC0_PROGRAM_VERIFIER.with_config(system_cfg)),
            },
            #[cfg(feature = "pico")]
            ProverSystemConfig::Pico(system_cfg) => AmdSevSnpProver {
                kds: KDS::new(),
                contract,
                cfg,
                verifier: Box::new(PICO_PROGRAM_VERIFIER.with_config(system_cfg)),
            },
        }
    }

    /// Returns the zero-knowledge coprocessor type used by this prover.
    pub fn get_zk_type(&self) -> ZkCoProcessorType {
        self.verifier.zktype()
    }

    /// Returns the program identifiers for verifier circuits.
    pub fn get_program_id(&self) -> ProgramId {
        ProgramId {
            verifier_id: self.verifier.program_id(),
            verify_proof_id: self.verifier.verify_proof_id(),
        }
    }

    /// Converts a raw ZK proof into a format suitable for onchain verification.
    pub fn encode_proof_for_onchain(&self, proof: &RawProof) -> anyhow::Result<Bytes> {
        self.verifier.onchain_proof(proof)
    }

    /// Uploads verifier program image to the remote proving service.
    pub fn upload_program_images(&self) -> anyhow::Result<ProgramId> {
        self.verifier.upload_image()?;
        Ok(self.get_program_id())
    }

    /// Generates a zero-knowledge proof for a single AMD SEV-SNP attestation report.
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
        if !self.cfg.skip_time_validity_check {
            cert_chain.check_valid(timestamp)?;
        }

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
        } else {
            tracing::warn!("Contract not provided, may lead to attestation failures and increased costs. Not recommended for production.");
        }

        Ok(VerifierInput {
            timestamp,
            rawReport: raw_report,
            vekDerChain: cert_chain.to_ders(),
        })
    }

    /// Builds a complete proof result with all metadata for blockchain submission.
    pub fn create_onchain_proof(&self, raw_proof: RawProof) -> anyhow::Result<OnchainProof> {
        Ok(OnchainProof::new_from_program(
            &*self.verifier,
            self.get_program_id(),
            raw_proof,
        )?)
    }

    /// Verifies a zero-knowledge proof on the Ethereum blockchain via smart contract.
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
