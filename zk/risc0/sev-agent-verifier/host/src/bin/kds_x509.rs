// TODO: Currently only upserts issuer certs to KDS
// TODO: support VLEK or VCEK upserts

use alloy::dyn_abi::SolType;
use alloy::primitives::Address;
use anyhow::{Error, Result};
use clap::{Args, Parser, Subcommand};
use risc0_ethereum_contracts::{self, groth16};
use risc0_zkvm::{
    compute_image_id, default_prover, ExecutorEnv, InnerReceipt::Groth16, ProverOpts,
};
use std::{fs::read, path::PathBuf};

use host::chain::{kds as OnChainKds, ChainConfig};
use host::code::x509::X509_CHAIN_VERIFIER_ELF;
use host::utils::certs::{kds::*, pem_to_der};
use host::{constants::*, prover_is_bonsai};

#[derive(Parser)]
#[command(name = "On-Chain KDS CLI")]
#[command(version = "1.0")]
#[command(about = "Performs a verification on SEV-SNP VEK Certificate Chain, then upserts to on-chain KDS", long_about = None)]
struct Cli {
    #[command(subcommand)]
    commands: Commands,
}

#[derive(Subcommand)]
enum Commands {
    ImageID,
    Upsert(VekArgs),
}

#[derive(Args)]
struct VekArgs {
    /// Required: If the user does not specify processor model
    #[arg(short = 'c', long = "vek-ca-chain", value_name = "PEM_PATH")]
    ca_chain: PathBuf,

    #[command(flatten)]
    chain: ChainArgs,
}

#[derive(Args)]
struct ChainArgs {
    /// Chain RPC URL
    #[arg(long = "rpc", value_name = "RPC_URL", default_value_t = String::from(RPC_URL))]
    rpc_url: String,

    /// The address of the KDS Contract
    #[arg(long = "kds_address", default_value_t = KDS_ADDRESS)]
    kds_address: Address,

    /// The private key of the user's wallet
    #[arg(short = 'w', long = "wallet-key")]
    wallet_key: String,
}

// #[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
// enum ProcessorOption {
//     /// 7003 series AMD EPYC Processor
//     Milan,
//     /// 9004 series AMD EPYC Processor
//     Genoa,
//     /// 97x4 series AMD EPYC Processor
//     Bergamo,
//     /// 8004 series AMD EPYC Processor
//     Siena
// }

// #[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
// enum CertType {
//     /// AMD SEV Signing Key (ASK) certificate and AMD Root Signing Key (ARK) certificate
//     /// returned as a single PEM file
//     Issuer,
//     /// Versioned Chip Endorsement Key (VCEK) certificate
//     VCEK,
//     /// Versioned Loaded Endorsement Key (VLEK) certificate
//     VLEK
// }

fn main() -> Result<()> {
    let cli = Cli::parse();
    env_logger::init();

    match cli.commands {
        Commands::ImageID => {
            let image_id = compute_image_id(X509_CHAIN_VERIFIER_ELF)?.to_string();
            println!("X509 ImageID: {}", image_id);
        }
        Commands::Upsert(args) => {
            let rt = tokio::runtime::Runtime::new().unwrap();

            println!("Initializing on-chain provider...");
            let mut chain_config =
                ChainConfig::new(args.chain.rpc_url.as_str(), SEV_AGENT_VERIFIER_ADDRESS);
            chain_config.set_wallet(&args.chain.wallet_key);
            log::info!("Wallet configured successfully...");
            log::debug!("{:?}", chain_config.wallet.as_ref().unwrap());
            println!("Successfully initialized chain.");

            // First, we will check if users provided the issuer chain
            // if left blank, most likely is because they intend to upload the VLEK leaf cert
            // In this case, we need to make sure the issuer already exists on-chain
            let issuer_chain_vec;
            // if let Some(issuer_chain) = args.ca_chain.as_ref() {
            // let issuer_chain_pem_data = read(issuer_chain)?;
            let issuer_chain_pem_data = read(&args.ca_chain)?;
            issuer_chain_vec = pem_to_der(&issuer_chain_pem_data);
            // }
            // else {
            //     issuer_chain_vec = rt.block_on(OnChainKds::read::fetch_ca(
            //         &chain_config,
            //         Some(args.chain.kds_address.clone()),
            //         &sev_snp_lib::types::ProcType::Milan, // TEMP
            //         &sev_snp_lib::types::CertType::VCEK // TEMP
            //     ))?;
            // }

            let (_x509_journal, x509_seal) = get_x509_proof(issuer_chain_vec.clone())?;

            let receipt = rt.block_on(OnChainKds::write::upsert_vek_cert_chain(
                &chain_config,
                Some(args.chain.kds_address.clone()),
                &issuer_chain_vec,
                &x509_seal,
            ))?;

            println!("Tx hash: {}", receipt.transaction_hash.to_string());
        }
    }

    Ok(())
}

fn get_x509_proof(cert_chain: Vec<Vec<u8>>) -> Result<(Vec<u8>, Vec<u8>)> {
    assert!(prover_is_bonsai(), "Bonsai Prover only");

    // Step 1: ABI-encode cert-chain
    let input = OnChainKds::InputBytesType::abi_encode_params(&cert_chain);

    // Step 2: Get Proof
    log::info!("Sending input to Bonsai...");
    let env = ExecutorEnv::builder().write_slice(&input).build()?;
    let receipt = default_prover()
        .prove_with_opts(env, X509_CHAIN_VERIFIER_ELF, &ProverOpts::groth16())?
        .receipt;

    assert!(
        receipt
            .verify(compute_image_id(X509_CHAIN_VERIFIER_ELF)?)
            .is_ok(),
        "Failed to verify X509 proof"
    );

    // Step 3: Ret
    let journal = receipt.journal.bytes.clone();
    let seal;
    if let Groth16(snark_receipt) = receipt.inner {
        seal = groth16::encode(snark_receipt.seal)?;
    } else {
        return Err(Error::msg("Not a Groth16 receipt"));
    }

    Ok((journal, seal))
}
