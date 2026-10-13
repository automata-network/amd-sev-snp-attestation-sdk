<div align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/automata-network/automata-brand-kit/main/PNG/ATA_White%20Text%20with%20Color%20Logo.png">
    <source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/automata-network/automata-brand-kit/main/PNG/ATA_Black%20Text%20with%20Color%20Logo.png">
    <img src="https://raw.githubusercontent.com/automata-network/automata-brand-kit/main/PNG/ATA_White%20Text%20with%20Color%20Logo.png" width="50%">
  </picture>
</div>

# Automata AMD SEV-SNP Attestation SDK
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

## Overview
Automata AMD SEV-SNP Attestation SDK is the most-feature complete SDK for AMD SEV-SNP development, it consists of two parts:

* SEV-SNP library: it helps developers to generate the AMD SEV-SNP Attestation Report in different cloud service providers (CSP).
* Risc0 and Succinct ZK host and guest programs to interact with the corresponding zkVM servers to generate the proofs, and constructs the [Automata AMD SEV-SNP Attestation](#deployment-information) contract calls to perform the on-chain verification.

### Environment Preparation
Refer to [SEV-SNP](./crates/sev-snp/README.md) to setup the AMD SEV-SNP CVM in different cloud service providers (CSP).

## AMD SEV-SNP Attestation Generation
Use [SEV-SNP](./crates/sev-snp/README.md#generate-attestation) to generate the AMD SEV-SNP Attestation Report with VEK Cert, you can find an example in [sev_snp_attestation](./crates/sev-snp/examples/attestation.rs).

## AMD SEV-SNP Attestation Verification
Generate a RISC0 or SP1 proof from the attestation report and VEK certificate chain, then call [verifyAndAttestWithZKProof](./contracts/src/SEVAgentAttestation.sol). Always check that the returned `VerifierJournal.result` is `VerificationResult.Success`: root-certificate and timestamp failures can return an error result without reverting. Applications must also enforce their workload, TCB and certificate-revocation policies.

```solidity
/**
 * @param output the zkVM output.
 * @param zkCoprocessor 1 - RiscZero, 2 - Succinct.
 * @param proofBytes the zk proof.
*/
function verifyAndAttestWithZKProof(
    bytes calldata output,
    ZkCoProcessorType zkCoprocessor,
    bytes calldata proofBytes
) external returns (VerifierJournal memory parsed);
```

This overload uses the latest allowed program. To select a specific allowed program, use the four-argument overload `(output, zkCoprocessor, programVKey, proofBytes)`.

### Deployment Information

See the [contract guide](contracts/README.md) for deployment and SP1 program configuration.

| Network | Chain ID | AMD attestation | SP1 verifier | RISC0 verifier |
| --- | --- | --- | --- | --- |
| Ethereum Mainnet | 1 | [0x3e6d0B383C915739cBBE75438C9a339BD63b97C9](https://etherscan.io/address/0x3e6d0B383C915739cBBE75438C9a339BD63b97C9#code) | [0x397A5f7f3dBd538f23DE225B51f532c34448dA9B](https://etherscan.io/address/0x397A5f7f3dBd538f23DE225B51f532c34448dA9B#code) | Not configured |
| Ethereum Sepolia | 11155111 | [0x84d19f7F2e07766ea16D1c24f7e0828FA11273A2](https://sepolia.etherscan.io/address/0x84d19f7F2e07766ea16D1c24f7e0828FA11273A2#code) | [0x397A5f7f3dBd538f23DE225B51f532c34448dA9B](https://sepolia.etherscan.io/address/0x397A5f7f3dBd538f23DE225B51f532c34448dA9B#code) | [0x925d8331ddc0a1F0d96E68CF073DFE1d92b69187](https://sepolia.etherscan.io/address/0x925d8331ddc0a1F0d96E68CF073DFE1d92b69187#code) |
| Ethereum Hoodi | 560048 | [0x89981202BDd1d19Cb5AfaFe74c847b87982b6B9C](https://hoodi.etherscan.io/address/0x89981202BDd1d19Cb5AfaFe74c847b87982b6B9C#code) | [0x7DA83eC4af493081500Ecd36d1a72c23F8fc2abd](https://hoodi.etherscan.io/address/0x7DA83eC4af493081500Ecd36d1a72c23F8fc2abd#code) | [0x32Db7dc407AC886807277636a1633A1381748DD8](https://hoodi.etherscan.io/address/0x32Db7dc407AC886807277636a1633A1381748DD8#code) |

### Latest AMD SP1 program

`amd_sev_snp.v1` · SP1 SDK **6.4.0** · Groth16

```text
vk_bytes / programVKey (on-chain):
0x007589387c69b403fe8d2b0e1c7db05175155daff7125fc981ac6ecd1985d18c

vk_hash (remote prover):
0x3ac49c3e1a6d00ff51a561c347db051728aaed7f5c497f260358dd9a1985d18c
```

The local SDK examples use a different bundled program; its identifiers do not match those above.

### ZK Optimization

#### Risc0
To get started, you need to have the following installed:

* [Rust](https://doc.rust-lang.org/cargo/getting-started/installation.html)
* [Foundry](https://getfoundry.sh/)
* [RISC Zero](https://dev.risczero.com/api/zkvm/install)

##### Configuring Boundless

With the Boundless proving network, you can produce a Groth16 SNARK proof that is verifiable on-chain.
You can get started by setting the following environment variables:

```bash
export BOUNDLESS_RPC_URL="https://..."  # Boundless network RPC endpoint
export BOUNDLESS_PRIVATE_KEY="0x..."    # Your wallet private key (hex-encoded)
export PINATA_JWT="..."                  # Pinata JWT for IPFS storage (for ELF uploads)
```

For more information, see the [Boundless documentation](https://docs.boundless.xyz/).

#### Succinct
To get started, you need to have the following installed:

* [Rust](https://doc.rust-lang.org/cargo/getting-started/installation.html)
* [SP1](https://docs.succinct.xyz/docs/sp1/getting-started/install)
* [Docker](https://docs.docker.com/get-started/get-docker/)

The local SDK declares SP1 `^5.2.1` dependencies and generates Groth16 proofs. Use the toolchain compatible with this repository when running the local examples; the latest program listed above uses SP1 SDK 6.4.0.

For network proving, configure your proving account:

```bash
export SP1_PROVER=network
export SP1_PRIVATE_KEY="0x..."  # Proving account private key
# Optional: export SP1_RPC_URL="<proving network endpoint>"
```

## Using The Prover SDK

The prover supports the following strategies for each zkVM backend.

### Strategy Enums

- `SP1ProvingStrategy`: `Dev`, `Local`, `Network`
- `RiscZeroProvingStrategy`: `Dev`, `Local`, `Boundless`
- `PicoProvingStrategy`: `Dev`, `Local`, `Marketplace`

### Rust API Example (SP1)

Run from the repository root with the `sp1` feature enabled. Replace the sample report with your own report for deployment use; its certificates must be valid at the supplied timestamp. On-chain verification also requires a matching allowed program and submission within `maxTimeDiff`.

```rust,no_run
use amd_sev_snp_attestation_prover::{
    AmdSevSnpProver, ProverConfig, SP1ProverConfig, SP1ProvingStrategy,
};

fn main() -> anyhow::Result<()> {
    let cfg = ProverConfig::sp1_with(SP1ProverConfig {
        strategy: SP1ProvingStrategy::Local,
        private_key: None,
        rpc_url: None,
        signer: None,
    });
    let prover = AmdSevSnpProver::new(cfg, None);

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    let report_with_chain = std::fs::read("samples/attestation_azure_snp.json")?;
    let decoded = amd_sev_snp_attestation_prover::utils::AttestationReportWithVekCertChain::decode(&report_with_chain)?;
    let proof = prover.prove_attestation_report(timestamp, decoded.report, decoded.vek_certs)?;
    std::fs::write("proof.json", proof.encode_json()?)?;
    Ok(())
}
```

### Rust API Example (RISC0)

```rust,no_run
use amd_sev_snp_attestation_prover::{
    AmdSevSnpProver, ProverConfig, RiscZeroProverConfig, RiscZeroProvingStrategy,
};

fn main() -> anyhow::Result<()> {
    let cfg = ProverConfig::risc0_with(RiscZeroProverConfig {
        strategy: RiscZeroProvingStrategy::Boundless,
        ..Default::default()
    });
    let _prover = AmdSevSnpProver::new(cfg, None);
    Ok(())
}
```

### Rust API Example (Pico)

```rust,no_run
use amd_sev_snp_attestation_prover::{
    AmdSevSnpProver, PicoProverConfig, PicoProvingStrategy, ProverConfig,
};

fn main() -> anyhow::Result<()> {
    let cfg = ProverConfig::pico_with(PicoProverConfig {
        proving_strategy: PicoProvingStrategy::Local,
        marketplace: None,
    });
    let _prover = AmdSevSnpProver::new(cfg, None);
    Ok(())
}
```

## CLI Proving Modes

Select the backend with a subcommand:

```bash
snp-attest-cli prove <sp1|risc0|pico> ...
snp-attest-cli upload <sp1|risc0|pico> ...
snp-attest-cli program-id <sp1|risc0|pico>
```

### Mode Matrix

| Backend | Strategy Flag | Modes | Remote Required |
| ------- | ------------- | ----- | --------------- |
| SP1 | `--strategy` | `dev`, `local`, `network` | only `network` |
| RISC0 | `--strategy` | `dev`, `local`, `boundless` | only `boundless` |
| Pico | `--strategy` | `dev`, `local`, `marketplace` | only `marketplace` |

`--dev` is still supported and forces `dev` strategy regardless of backend strategy flag.

### Pico Marketplace Inputs

Build `snp-attest-cli` with the `pico` feature to use this backend. Pico marketplace proving (`--strategy marketplace`) uses the Brevis prover marketplace on Base.
You can configure it via CLI flags or env vars:

```bash
# required for marketplace proving
export PICO_RPC_URL="https://mainnet.base.org"
export PICO_PROVER_KEY="0x..."
export PICO_PROGRAM_URL="ipfs://..."

# optional tuning
export MARKETPLACE_POLL_BLOCK_INTERVAL=10
```

CLI flags:

```bash
snp-attest-cli prove pico \
  --strategy marketplace \
  --pico-rpc-url https://mainnet.base.org \
  --pico-prover-key 0x... \
  --elf-url ipfs://... \
  --poll-interval 30 \
  --duration 86400 \
  --report samples/attestation_azure_snp.json
```

## Acknowledgements
We would like to acknowledge the projects below whose previous work has been instrumental in making this project a reality.

* [virtee/sev](https://github.com/virtee/sev), an implementation of the [AMD Secure Encrypted Virtualization (SEV)](https://www.amd.com/content/dam/amd/en/documents/epyc-technical-docs/programmer-references/55766_SEV-KM_API_Specification.pdf) APIs and the [SEV Secure Nested Paging Firmware (SNP)](https://www.amd.com/content/dam/amd/en/documents/epyc-technical-docs/specifications/56860.pdf) ABIs.

## Disclaimer
This project is under development. All source code and features are not production ready.
