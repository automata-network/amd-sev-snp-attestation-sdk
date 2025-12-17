use std::sync::Arc;

use alloy_network::{Ethereum, EthereumWallet, TransactionBuilder};
use alloy_primitives::{Address, Bytes, B256};
use alloy_provider::{PendingTransactionBuilder, Provider, ProviderBuilder};
use alloy_rpc_types::{TransactionReceipt, TransactionRequest};
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::SolCall;
use amd_sev_snp_attestation_verifier::stub::{
    ISnpAttestation::*, ProcessorType, VerifierJournal, ZkCoProcessorType,
};
use anyhow::{anyhow, Context};

use crate::OnchainProof;

#[derive(Clone)]
pub struct SnpVerifierContract {
    contract: Address,
    client: Arc<Box<dyn Provider>>,
    signer_addr: Option<Address>,
}

impl SnpVerifierContract {
    pub fn dial(
        endpoint: &str,
        contract: Address,
        private_key: Option<&str>,
    ) -> anyhow::Result<Self> {
        let url = endpoint.try_into()?;

        let mut signer_addr = None;

        let provider: Box<dyn Provider> = match private_key {
            Some(pk) => {
                let signer = pk.parse::<PrivateKeySigner>()?;
                signer_addr = Some(signer.address());
                let wallet = EthereumWallet::new(signer);
                let provider = ProviderBuilder::new().wallet(wallet).connect_http(url);
                Box::new(provider)
            }
            None => {
                let provider = ProviderBuilder::new().connect_http(url);
                Box::new(provider)
            }
        };

        Ok(Self {
            contract,
            signer_addr,
            client: Arc::new(provider),
        })
    }

    pub async fn call<T: SolCall>(&self, call: &T) -> anyhow::Result<T::Return> {
        let tx = TransactionRequest::default()
            .with_call(call)
            .to(self.contract);
        let result = self
            .client
            .call(tx)
            .await
            .with_context(|| format!("contract={:?}", self.contract))?;
        let result = T::abi_decode_returns(&result)?;
        Ok(result)
    }

    pub async fn transact<T: SolCall>(
        &self,
        call: &T,
    ) -> anyhow::Result<PendingTransactionBuilder<Ethereum>> {
        let signer_addr = self.signer_addr.ok_or_else(|| {
            anyhow!(
                "No signer address provided, cannot send transaction to contract: {:?}",
                self.contract
            )
        })?;
        let tx = TransactionRequest::default()
            .with_call(call)
            .with_from(signer_addr)
            .to(self.contract);

        let result = self.client.send_transaction(tx).await?;
        Ok(result)
    }

    pub async fn verify_proof(&self, proof: &OnchainProof) -> anyhow::Result<VerifierJournal> {
        if proof.onchain_proof.len() == 0 {
            return Err(anyhow!(
                "Proof does not contain an on-chain proof, unable to verify on-chain."
            ));
        }
        let journal = proof.raw_proof.journal.clone();
        let proof_bytes = proof.onchain_proof.clone();
        let zk = proof.zktype;

        Ok(self.call_verify(zk, proof_bytes, journal).await?)
    }

    pub async fn call_verify(
        &self,
        zk: ZkCoProcessorType,
        proof: Bytes,
        journal: Bytes,
    ) -> anyhow::Result<VerifierJournal> {
        let call = verifyAndAttestWithZKProof_0Call {
            output: journal.clone(),
            zkCoprocessor: zk,
            proofBytes: proof.clone(),
        };
        Ok(self
            .call(&call)
            .await
            .with_context(|| format!("proof: {}, journal: {}", proof, journal))?)
    }

    pub async fn submit_proof(&self, proof: &OnchainProof) -> anyhow::Result<TransactionReceipt> {
        if proof.onchain_proof.len() == 0 {
            return Err(anyhow!(
                "Proof does not contain an on-chain proof, unable to verify on-chain."
            ));
        }
        let journal = proof.raw_proof.journal.clone();
        let proof_bytes = proof.onchain_proof.clone();
        let zk = proof.zktype;

        let receipt = self.submit_verify(zk, proof_bytes, journal).await?;
        let receipt = receipt.get_receipt().await?;
        Ok(receipt)
    }

    pub async fn submit_verify(
        &self,
        zk: ZkCoProcessorType,
        proof: Bytes,
        journal: Bytes,
    ) -> anyhow::Result<PendingTransactionBuilder<Ethereum>> {
        let call = verifyAndAttestWithZKProof_0Call {
            output: journal.clone(),
            zkCoprocessor: zk,
            proofBytes: proof.clone(),
        };
        Ok(self
            .transact(&call)
            .await
            .with_context(|| format!("proof: {}, journal: {}", proof, journal))?)
    }

    pub async fn root_certs(&self, processor_model: ProcessorType) -> anyhow::Result<B256> {
        Ok(self
            .call(&rootCertsCall {
                processorModel: processor_model,
            })
            .await?)
    }

    pub async fn program_id(&self, zk: ZkCoProcessorType) -> anyhow::Result<B256> {
        let call = programIdentifierCall {
            zkCoProcessorType: zk,
        };
        Ok(self.call(&call).await?)
    }

    pub async fn max_time_diff(&self) -> anyhow::Result<u64> {
        Ok(self.call(&maxTimeDiffCall {}).await?)
    }

    pub async fn batch_query_cert_cache(
        &self,
        processor_models: Vec<ProcessorType>,
        certs_digests: Vec<Vec<B256>>,
    ) -> anyhow::Result<Vec<u8>> {
        if certs_digests.is_empty() {
            return Ok(vec![]);
        }

        for report_certs in &certs_digests {
            let len = report_certs.len();
            if len == 0 || len > 8 {
                return Err(anyhow!(
                    "Too many certificate chains provided, maximum is 8, got: {len}"
                ));
            }
        }

        let result = self
            .call(&checkTrustedIntermediateCertsCall {
                processorModels: processor_models,
                _reportCerts: certs_digests,
            })
            .await?;
        Ok(result)
    }
}
