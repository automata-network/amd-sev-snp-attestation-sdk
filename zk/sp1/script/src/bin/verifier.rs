use sp1_sdk::{utils, HashableKey, ProverClient, SP1Stdin};

use alloy::primitives::{address, Address};
use anyhow::Result;
use clap::{Args, Parser, Subcommand, ValueEnum};
use guest_program_lib::{serialize_guest_input, ApiOpt, DecodedOutput};
use reqwest::blocking::get;
use sev_snp_lib::attestation::AttestationReport;
use sev_snp_lib::types::{CertType, ProcType};
use std::{fs::read_to_string, path::PathBuf};
use x509_parser::prelude::{parse_x509_certificate, Pem};

pub const AMD_SEV_SNP_ELF: &[u8] = include_bytes!("../../../elf/riscv32im-succinct-zkvm-elf");
pub const RPC_URL: &str = "https://1rpc.io/ata/testnet";
pub const SEV_AGENT_VERIFIER_ADDRESS: Address =
    address!("BfAd01Ffa59C4A70d80b923Ab591F5b7dE98b220");

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

fn main() {
    utils::setup_logger();
    let cli = Cli::parse();

    match cli.commands {
        Commands::Verify(args) => {
            let output_data = read_to_string(&args.agent_output_path).unwrap();
            let output = serde_json::from_str(output_data.as_str()).unwrap();

            let api_opt = ApiOpt::from_output(&output);
            println!("API Option: {:?}", api_opt);

            let decoded_output = DecodedOutput::decode_output(output);
            // println!("decoded_output: {:?}", decoded_output);
            let raw_sev_attestation_report = decoded_output.sev_snp_attestation.sev_att;
            println!(
                "raw_sev_attestation_report: {:?}",
                raw_sev_attestation_report
            );

            let mut vek_cert_chain = vec![decoded_output.sev_snp_attestation.vek_der.clone()];
            let (_, vek_leaf) = parse_x509_certificate(&vek_cert_chain[0]).unwrap();
            let vek_type =
                AttestationReport::from_bytes(&raw_sev_attestation_report).get_signing_cert_type();

            let proc_type = sev_snp_lib::get_processor_model_from_vek(vek_type, &vek_leaf);
            println!("vek_type: {:?}, proc_type: {:?}", vek_type, proc_type);

            let vcek_ca_pem_chain = fetch_vek_issuer_ca_pem_chain(&proc_type, &vek_type).unwrap();
            vek_cert_chain = [vek_cert_chain, pem_to_der(&vcek_ca_pem_chain)].concat();
            println!("Successfully fetched VEK Certificate Chain from the KDS...");

            let ima_measurement = None;
            let tpm = None;
            let nonce = vec![0];

            let serialized_input = serialize_guest_input(
                api_opt,
                &nonce,
                &raw_sev_attestation_report,
                vek_cert_chain,
                ima_measurement,
                tpm,
            );
            println!("Begin submitting input to be proven...");

            let mut stdin = SP1Stdin::new();
            stdin.write_slice(&serialized_input);

            let client = ProverClient::new();

            // Execute the program first
            let (ret, report) = client
                .execute(AMD_SEV_SNP_ELF, stdin.clone())
                .run()
                .unwrap();
            println!(
                "executed program with {} cycles",
                report.total_instruction_count()
            );

            // Generate the proof
            let (pk, vk) = client.setup(AMD_SEV_SNP_ELF);
            let proof = client.prove(&pk, stdin.clone()).groth16().run().unwrap();
            // let proof = client.prove(&pk, stdin.clone()).plonk().run().unwrap();

            // Verify proof
            client.verify(&proof, &vk).expect("Failed to verify proof");
            println!("Successfully verified proof.");

            let ret_slice = ret.as_slice();
            let output_len = u16::from_le_bytes([ret_slice[0], ret_slice[1]]) as usize;
            let mut output = Vec::with_capacity(output_len);
            output.extend_from_slice(&ret_slice[2..2 + output_len]);

            println!("Execution Output: {}", hex::encode(ret_slice));
            println!(
                "Proof pub value: {}",
                hex::encode(proof.public_values.as_slice())
            );
            println!("VK: {}", vk.bytes32().to_string().as_str());
            println!("Proof: {}", hex::encode(proof.bytes()));
        }
    }
}

// PEM chain to DER-encoded bytes conversion
// Provide PEM data directly to this function call
fn pem_to_der(pem_chain: &[u8]) -> Vec<Vec<u8>> {
    let mut der_chain: Vec<Vec<u8>> = Vec::new();

    for pem in Pem::iter_from_buffer(pem_chain) {
        let current_pem_content = pem.unwrap().contents;
        der_chain.push(current_pem_content);
    }

    der_chain
}

fn fetch_vek_issuer_ca_pem_chain(
    processor_model: &ProcType,
    cert_type: &CertType,
) -> Result<Vec<u8>> {
    let kds_url = format!(
        "https://kdsintf.amd.com/{}/v1/{}/cert_chain",
        cert_type.to_str(),
        processor_model.to_str()
    );

    let res = fetch_certificate(kds_url.as_str())?;
    Ok(res)
}

fn fetch_certificate(url_str: &str) -> Result<Vec<u8>> {
    let ret_data = get(url_str)?.bytes()?.to_vec();
    Ok(ret_data)
}
