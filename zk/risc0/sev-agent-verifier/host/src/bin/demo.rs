use risc0_ethereum_contracts::{self, groth16};
use risc0_zkvm::{compute_image_id, InnerReceipt::Groth16, ProverOpts};

use alloy::primitives::Address;
use anyhow::{Error, Result};
use clap::{Args, Parser, Subcommand, ValueEnum};
use std::{
    fs::read_to_string,
    path::PathBuf
};
use x509_parser::prelude::parse_x509_certificate;

use host::{
    chain::{send_verify_journal_on_chain, verify_journal_on_chain, ChainConfig},
    utils::{
        certs::{kds::*, pem_to_der, tpm::get_tpm_cert_der_chain},
        parser::DecodedOutput,
        serializer::serialize_guest_input,
        ApiOpt, Tpm,
    },
    constants::{SEV_AGENT_VERIFIER_ADDRESS, RPC_URL},
    code::sev_guest::SEV_AGENT_VERIFIER_GUEST_ELF,
    prove_input_and_get_journal,
    prover_is_bonsai,
};
use sev_snp_lib::attestation::AttestationReport;

#[derive(Parser)]
#[command(name = "SEV Agent Verifier CLI")]
#[command(version = "1.0")]
#[command(about = "Performs verification on SEV-SNP Attestation Reports", long_about = None)]
struct Cli {
    #[command(subcommand)]
    commands: Commands,
}

#[derive(Subcommand)]
enum Commands {
    ImageID,
    Verify(AgentVerifierArgs),
}

#[derive(Args)]
struct AgentVerifierArgs {
    /// The path of the output JSON file fetched from the Agent Service.
    #[arg(short = 'o', long = "output", value_name = "AGENT_OUTPUT_PATH")]
    agent_output_path: PathBuf,

    /// Select a proof option. Defaults to Groth16, with the assumption
    /// that the Guest program is running on Bonsai
    #[arg(value_enum, short = 'p', long = "prove-option", default_value_t = ProveOption::Groth16)]
    prove_option: ProveOption,

    #[command(flatten)]
    chain: ChainArgs,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum ProveOption {
    /// Generates the default STARK receipt
    Default,
    /// Generates a Groth16 Receipt.
    /// Note: May fail when attempting to generate Groth16 receipt locally
    /// on Apple Silicon machines.
    Groth16,
}

#[derive(Args)]
struct ChainArgs {
    /// Chain RPC URL
    #[arg(long = "rpc", value_name = "RPC_URL", default_value_t = String::from(RPC_URL))]
    rpc_url: String,

    /// The address of SEVAgentVerifier contract.
    /// This is where proofs are verified on-chain.
    #[arg(long = "verifier_address", default_value_t = SEV_AGENT_VERIFIER_ADDRESS)]
    verifier_address: Address,

    /// Optional: For users intend to explicitly submit a transaction for verification.
    /// If left blank, a static call is made instead.
    #[arg(short = 'w', long = "wallet-key")]
    wallet_key: Option<String>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    env_logger::init();

    match cli.commands {
        Commands::ImageID => {
            let image_id = compute_image_id(SEV_AGENT_VERIFIER_GUEST_ELF)?.to_string();
            println!("SEV_AGENT_VERIFIER ImageID: {}", image_id);
        }
        Commands::Verify(args) => {
            let rt = tokio::runtime::Runtime::new().unwrap();

            println!("Initializing on-chain provider...");
            let mut chain_config =
                ChainConfig::new(args.chain.rpc_url.as_str(), args.chain.verifier_address);
            if let Some(wallet) = args.chain.wallet_key.as_ref() {
                chain_config.set_wallet(wallet);
                log::info!("Wallet configured successfully...");
                log::debug!("{:?}", chain_config.wallet.as_ref().unwrap());
            }
            println!("Successfully initialized chain.");

            println!("Reading Agent Service output...");

            let output_data = read_to_string(&args.agent_output_path).unwrap();
            let output = serde_json::from_str(output_data.as_str()).unwrap();

            // let api_opt = ApiOpt::from_output(&output);
            let api_opt = ApiOpt::Sev;
            println!("API Option: {:?}", api_opt);

            let decoded_output = DecodedOutput::decode_output(output);
            println!("decoded_output: {:?}", decoded_output);
            let raw_sev_attestation_report = decoded_output.sev_snp_attestation.sev_att;
            println!("raw_sev_attestation_report: {:?}", raw_sev_attestation_report);

            // let report = AttestationReport::from_bytes(&raw_sev_attestation_report);
            // let mut vek_cert_chain = vec![fetch_vcek_pem(&sev_snp_lib::types::ProcType::Milan, &report).unwrap()];
            // let (_, vek_leaf) = parse_x509_certificate(&vek_cert_chain[0]).unwrap();
            // let vek_type = report.get_signing_cert_type();
            // println!("vek_type: {:?}", vek_type);

            // let proc_type = sev_snp_lib::get_processor_model_from_vek(vek_type, &vek_leaf);
            // println!("proc_type: {:?}", proc_type);

            let mut vek_cert_chain = vec![decoded_output.sev_snp_attestation.vek_der.clone()];
            let (_, vek_leaf) = parse_x509_certificate(&vek_cert_chain[0]).unwrap();
            let vek_type =
                AttestationReport::from_bytes(&raw_sev_attestation_report).get_signing_cert_type();

            let proc_type = sev_snp_lib::get_processor_model_from_vek(vek_type, &vek_leaf);
            println!("vek_type: {:?}, proc_type: {:?}", vek_type, proc_type);

            let vcek_ca_pem_chain = fetch_vek_issuer_ca_pem_chain(&proc_type, &vek_type).unwrap();
            vek_cert_chain = [vek_cert_chain, pem_to_der(&vcek_ca_pem_chain)].concat();
            println!("Successfully fetched VEK Certificate Chain from the KDS...");

            let ima_measurement;
            if api_opt != ApiOpt::Sev {
                ima_measurement = Some(
                    decoded_output
                        .ima_measurement_log_content
                        .expect("Missing IMA log"),
                );
            } else {
                ima_measurement = None;
            }

            let tpm;
            if api_opt == ApiOpt::SevTpm {
                if let Some(tpm_att) = decoded_output.tpm_attestation {
                    let (_, ak_leaf) = parse_x509_certificate(&tpm_att.ak_der).unwrap();
                    let mut ak_der_chain = vec![tpm_att.ak_der.clone()];
                    ak_der_chain =
                        [ak_der_chain, get_tpm_cert_der_chain(&ak_leaf).unwrap()].concat();
                    println!("AK Certificate Chain found!");

                    let ek_der_chain = if let Some(ek_der) = tpm_att.ek_der {
                        let (_, ek_leaf) = parse_x509_certificate(&ek_der).unwrap();
                        let mut chain = vec![ek_der.clone()];
                        chain = [chain, get_tpm_cert_der_chain(&ek_leaf).unwrap()].concat();
                        println!("EK Certificate Chain found!");

                        Some(chain)
                    } else {
                        None
                    };

                    tpm = Some(Tpm {
                        quote: tpm_att.tpm_quote.clone(),
                        signature: tpm_att.tpm_raw_sig.clone(),
                        pcr10_hash_algo: tpm_lib::constants::TPM_ALG_SHA1,
                        pcr10_value: tpm_att.pcr_value,
                        ak_der_chain: ak_der_chain,
                        ek_der_chain: ek_der_chain,
                    });
                    println!("Successfully loaded TPM Attestation");
                } else {
                    return Err(Error::msg("Missing TPM Attestation"));
                }
            } else {
                tpm = None;
            }

            // let nonce = decoded_output.nonce.as_slice();
            let nonce = vec![0];

            let serialized_input = serialize_guest_input(
                api_opt,
                &nonce,
                &raw_sev_attestation_report,
                vek_cert_chain,
                ima_measurement.as_deref(),
                tpm,
            );

            println!("Begin submitting input to be proven...");
            let prove_option = match args.prove_option {
                ProveOption::Default => ProverOpts::default(),
                ProveOption::Groth16 => ProverOpts::groth16(),
            };
            let receipt = prove_input_and_get_journal(&serialized_input, prove_option)?;
            println!("A receipt has been successfully generated by the prover.");

            if let Groth16(snark_receipt) = receipt.inner {
                if prover_is_bonsai() {
                    println!("Sending proofs on-chain to be verified...");
                    let seal = groth16::encode(snark_receipt.seal)?;
                    let journal = receipt.journal.bytes;
                    log::info!("Journal: {}", hex::encode(&journal));
                    log::info!("Seal: {}", hex::encode(&seal));
                    if chain_config.wallet.as_ref().is_some() {
                        println!("Sending tx...");
                        let tx_receipt = rt.block_on(send_verify_journal_on_chain(
                            chain_config,
                            &journal,
                            &seal,
                        ))?;
                        let tx_hash = tx_receipt.transaction_hash.to_string();
                        println!("Tx hash: {}", tx_hash);
                    } else {
                        rt.block_on(verify_journal_on_chain(chain_config, &journal, &seal))?;
                    }
                }
            }
        }
    }

    println!("Job completed!");

    Ok(())
}
