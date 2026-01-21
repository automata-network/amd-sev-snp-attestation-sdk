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
* Risc0 and Succinct ZK host and guest programs to interact with the corresponding zkVM servers to generate the proofs, and constructs the [Automata AMD SEV-SNP Attestation](https://explorer-testnet.ata.network/address/0xDe510E1F9258c94c5520B717210a301Cc8297F1F) contract calls to perform the on-chain verification.

### Environment Preparation
Refer to [SEV-SNP](./sev-snp/README.md) to setup the AMD SEV-SNP CVM in different cloud service providers (CSP).

## AMD SEV-SNP Attestation Generation
Use [SEV-SNP](./sev-snp/README.md#generate-attestation) to generate the AMD SEV-SNP Attestation Report with VEK Cert, you can find an example in [sev_snp_attestation](./sev-snp/examples/attestation.rs).

## AMD SEV-SNP Attestation Verification
Combining the Attestation Generation and the ZK Optimization, you can generate an either Risc0 or SP1 ZK proof with the AMD SEV-SNP Attestation Report and the VEK Cert output, and verify it via [verifyAndAttestWithZKProof](https://explorer-testnet.ata.network:443/address/0xDe510E1F9258c94c5520B717210a301Cc8297F1F?tab=read_contract#57859ce0) method.

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
)
```

### Deployment Information

| Network | ChainID  | SEVAgentAttestation                        | SP1Verifier                                | RiscZeroGroth16Verifier                    |
| ------- | -------- | ------------------------------------------ | ------------------------------------------ | ------------------------------------------ |
| Sepolia | 11155111 | 0x84d19f7F2e07766ea16D1c24f7e0828FA11273A2 | 0x397A5f7f3dBd538f23DE225B51f532c34448dA9B | 0x925d8331ddc0a1F0d96E68CF073DFE1d92b69187 |
| Hoodi   | 560048   | 0x84d19f7F2e07766ea16D1c24f7e0828FA11273A2 | 0x7DA83eC4af493081500Ecd36d1a72c23F8fc2abd | 0x32Db7dc407AC886807277636a1633A1381748DD8 |
| Automata Testnet | 1398243 | 0x84d19f7F2e07766ea16D1c24f7e0828FA11273A2 | 0x7291752B7c1e0E69adF9801865b25435b0bE4Fc6 | 0xaE7F7EC735b6A90366e55f87780b36e7e6Ec3c65 |

| ZkType | Verifier ID | 
| ------ | ----------- | 
| Risc0  | 0x280160e5f541ac4a9015ae6bb4b65e0b4791354e30ff9a393dd50c3bb24dc377 | 
| SP1    | 0x00d2342d2400bed28302507269281dcb2c621bae91a0626796ce637f01c928d8 |

### ZK Optimization

#### Risc0
To get started, you need to have the following installed:

* [Rust](https://doc.rust-lang.org/cargo/getting-started/installation.html)
* [Foundry](https://getfoundry.sh/)
* [RISC Zero](https://dev.risczero.com/api/zkvm/install)

##### Configuring Boundless

With the Boundless proving network, you can produce a [Groth16 SNARK proof] that is verifiable on-chain.
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
* [SP1](https://docs.succinct.xyz/getting-started/install.html)
* [Docker](https://docs.docker.com/get-started/get-docker/)

***Note:*** *SP1 5.2 includes mainnet support by default. To request a whitelisted address for the SP1 production network, [complete the form here](https://docs.google.com/forms/d/e/1FAIpQLSd-X9uH7G0bvXH_kjptnQtNil8L4dumrVPpFE4t8Ci1XT1GaQ/viewform).*

With the SP1 Proving Network, you can produce a [Groth16 SNARK proof] or [Plonk SNARK proof] that is verifiable on-chain.
You can get started by setting the following environment variables with your whitelisted address:

```bash
export SP1_PROVER=network
export SP1_PRIVATE_KEY="0x..."  # Your whitelisted private key
# SP1_RPC_URL is optional - SP1 5.2 defaults to production mainnet endpoint
```

## Acknowledgements
We would like to acknowledge the projects below whose previous work has been instrumental in making this project a reality.

* [virtee/sev](https://github.com/virtee/sev), an implementation of the [AMD Secure Encrypted Virtualization (SEV)](https://www.amd.com/content/dam/amd/en/documents/epyc-technical-docs/programmer-references/55766_SEV-KM_API_Specification.pdf) APIs and the [SEV Secure Nested Paging Firmware (SNP)](https://www.amd.com/content/dam/amd/en/documents/epyc-technical-docs/specifications/56860.pdf) ABIs.

## Disclaimer
This project is under development. All source code and features are not production ready.
