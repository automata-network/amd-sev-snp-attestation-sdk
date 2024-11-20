use crate::chain::{ChainConfig, SEVAgentAttestation};
use alloy::{
    primitives::{Bytes, Address}, providers::ProviderBuilder, rpc::types::TransactionReceipt,
    transports::http::reqwest::Url,
};
use anyhow::Result;

use super::KDS;

pub async fn upsert_vek_cert_chain(
    config: &ChainConfig,
    kds_address_optional: Option<Address>,
    cert_chain: &Vec<Vec<u8>>,
    seal: &[u8],
) -> Result<TransactionReceipt> {
    let rpc_url: Url = config.rpc_url.parse().unwrap();

    let provider = ProviderBuilder::new()
        .with_recommended_fillers()
        .wallet(config.wallet.as_ref().expect("Missing wallet"))
        .on_http(rpc_url);

    let kds_address = match kds_address_optional {
        Some(kds) => kds,
        _ => {
            let sev_attestation_contract = SEVAgentAttestation::new(
                config.attestation_contract_address,
                &provider
            );
            sev_attestation_contract.kds().call().await?._0
        }
    };

    let kds_contract = KDS::new(kds_address, &provider);

    let mut cert_chain_input: Vec<Bytes> = Vec::with_capacity(cert_chain.len());

    for cert in cert_chain.iter() {
        cert_chain_input.push(Bytes::copy_from_slice(cert));
    }

    let tx_builder = kds_contract.upsertVekCaChain(cert_chain_input, Bytes::copy_from_slice(&seal));
    let tx_receipt = tx_builder.send().await?.get_receipt().await?;

    Ok(tx_receipt)
}
