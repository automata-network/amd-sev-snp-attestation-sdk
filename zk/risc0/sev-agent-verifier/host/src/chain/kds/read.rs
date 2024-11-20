use crate::chain::{ChainConfig, SEVAgentAttestation};
use alloy::{
    providers::ProviderBuilder,
    transports::http::reqwest::Url,
    primitives::Address
};
use anyhow::Result;

use sev_snp_lib::types::{CertType, ProcType};
use sev_snp_lib::attestation::TcbVersion as RustTcbVersion;

use super::{cert_type_to_solidity_enum, KDS};
use super::KDS::TcbVersion as SolidityTcbVersion;

pub async fn fetch_vek(
    config: &ChainConfig,
    kds_address_optional: Option<Address>,
    processor: &ProcType,
    vek_type: &CertType,
    reported_tcb: RustTcbVersion
) -> Result<Vec<Vec<u8>>> {
    let rpc_url: Url = config.rpc_url.parse().unwrap();
    let provider = ProviderBuilder::new().on_http(rpc_url);

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

    let kds_contract = KDS::new(
        kds_address,
        &provider
    );
    
    let solidity_reported_tcb = SolidityTcbVersion::from((
        reported_tcb.bootloader,
        reported_tcb.tee,
        reported_tcb.snp,
        reported_tcb.microcode
    ));

    let vek_ret = kds_contract.fetchVek(
        processor.to_u8(),
        cert_type_to_solidity_enum(vek_type),
        solidity_reported_tcb
    ).call().await?.vek;

    let mut ret = Vec::with_capacity(1);
    ret.push(vek_ret.to_vec());

    Ok(ret)
}

pub async fn fetch_ca(
    config: &ChainConfig,
    kds_address_optional: Option<Address>,
    processor: &ProcType,
    cert_type: &CertType
) -> Result<Vec<Vec<u8>>> {
    let rpc_url: Url = config.rpc_url.parse().unwrap();
    let provider = ProviderBuilder::new().on_http(rpc_url);

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

    let kds_contract = KDS::new(
        kds_address,
        &provider
    );

    let vek_ca_ret = kds_contract.fetchCa(
        processor.to_u8(),
        cert_type_to_solidity_enum(cert_type)
    ).call().await?;

    let mut ret = Vec::with_capacity(2);
    ret.push(vek_ca_ret.ask.to_vec());
    ret.push(vek_ca_ret.ark.to_vec());

    Ok(ret)
}