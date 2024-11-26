pub mod kds;

use alloy::{
    primitives::{Address, Bytes},
    providers::ProviderBuilder,
    rpc::types::TransactionReceipt,
    signers::{
        k256::ecdsa::SigningKey,
        local::PrivateKeySigner
    },
    network::EthereumWallet,
    sol,
    transports::http::reqwest::Url,
};

use anyhow::Result;

sol! {
    #[allow(missing_docs)]
    #[sol(rpc)]
    SEVAgentAttestation,
    "artifacts/SEVAgentAttestation.json"
}

#[derive(Debug)]
pub struct ChainConfig {
    pub rpc_url: String,
    pub attestation_contract_address: Address,
    pub wallet: Option<EthereumWallet>,
}

impl ChainConfig {
    pub fn new(rpc_url: &str, attestation_addr: Address) -> Self {
        ChainConfig {
            rpc_url: String::from(rpc_url),
            attestation_contract_address: attestation_addr,
            wallet: None,
        }
    }

    pub fn set_wallet(&mut self, wallet_key: &str) {
        let signer_key =
            SigningKey::from_slice(&hex::decode(wallet_key).unwrap()).expect("Invalid key");
        let wallet = EthereumWallet::from(PrivateKeySigner::from_signing_key(
            signer_key
        ));
        self.wallet = Some(wallet);
    }
}

pub async fn verify_journal_on_chain(
    config: ChainConfig,
    journal: &[u8],
    seal: &[u8],
) -> Result<()> {
    let rpc_url: Url = config.rpc_url.parse().unwrap();
    let provider = ProviderBuilder::new().on_http(rpc_url);
    let sev_attestation_contract =
        SEVAgentAttestation::new(config.attestation_contract_address, &provider);
    let call_builder = sev_attestation_contract.verifyAndAttestWithZKProof(
        Bytes::copy_from_slice(journal),
        1,
        Bytes::copy_from_slice(seal),
    );
    call_builder.call().await?;
    Ok(())
}

pub async fn send_verify_journal_on_chain(
    config: ChainConfig,
    journal: &[u8],
    seal: &[u8],
) -> Result<TransactionReceipt> {
    let rpc_url: Url = config.rpc_url.parse().unwrap();
    let provider = ProviderBuilder::new()
        .with_recommended_fillers()
        .wallet(config.wallet.expect("Missing wallet"))
        .on_http(rpc_url);
    let sev_attestation_contract =
        SEVAgentAttestation::new(config.attestation_contract_address, &provider);
    let tx_builder = sev_attestation_contract.verifyAndAttestWithZKProof(
        Bytes::copy_from_slice(journal),
        1,
        Bytes::copy_from_slice(seal),
    );
    let tx_receipt = tx_builder.send().await?.get_receipt().await?;
    Ok(tx_receipt)
}