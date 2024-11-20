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
* Risc0 and Succinct ZK host and guest programs to interact with the corresponding zkVM servers to generate the proofs, and constructs the [Automata AMD SEV-SNP Attestation]() contracts calls to perform the on-chain verification.

### Environment Preparation
Refer to [SEV-SNP](./sev-snp/README.md) to setup the AMD SEV-SNP CVM in different cloud service providers (CSP).

## AMD SEV-SNP Attestation Generation
Use [SEV-SNP](./sev-snp/README.md#generate-attestation) to generate the AMD SEV-SNP Attestation Report with VEK Cert, you can find an example in [sev_snp_attestation](./sev-snp/examples/attestation.rs).

## AMD SEV-SNP Attestation Verification
TODO

### ZK Optimization

#### Risc0
To get started, you need to have the following installed:

* [Rust](https://doc.rust-lang.org/cargo/getting-started/installation.html)
* [Foundry](https://getfoundry.sh/)
* [RISC Zero](https://dev.risczero.com/api/zkvm/install)

##### Configuring Bonsai

***Note:*** *To request an API key [complete the form here](https://bonsai.xyz/apply).*

With the Bonsai proving service, you can produce a [Groth16 SNARK proof] that is verifiable on-chain.
You can get started by setting the following environment variables with your API key and associated URL.

```bash
export BONSAI_API_KEY="YOUR_API_KEY" # see form linked above
export BONSAI_API_URL="BONSAI_URL" # provided with your api key
```

#### Succinct
To get started, you need to have the following installed:

* [Rust](https://doc.rust-lang.org/cargo/getting-started/installation.html)
* [SP1](https://docs.succinct.xyz/getting-started/install.html)
* [Docker](https://docs.docker.com/get-started/get-docker/)

***Note:*** *To request an whitelisted address, [complete the form here](https://docs.google.com/forms/d/e/1FAIpQLSd-X9uH7G0bvXH_kjptnQtNil8L4dumrVPpFE4t8Ci1XT1GaQ/viewform).*

With the SP1 Proving Network, you can produce a [Groth16 SNARK proof] or [Plonk SNARK proof] that is verifiable on-chain.
You can get started by setting the following environment variables with your whitelisted address and associated Proving Network.

```bash
export SP1_PROVER=network
export SP1_PRIVATE_KEY=""
```

## Acknowledgements
We would like to acknowledge the projects below whose previous work has been instrumental in making this project a reality.

* [virtee/sev](https://github.com/virtee/sev), an implementation of the [AMD Secure Encrypted Virtualization (SEV)](https://www.amd.com/content/dam/amd/en/documents/epyc-technical-docs/programmer-references/55766_SEV-KM_API_Specification.pdf) APIs and the [SEV Secure Nested Paging Firmware (SNP)](https://www.amd.com/content/dam/amd/en/documents/epyc-technical-docs/specifications/56860.pdf) ABIs.

## Disclaimer
This project is under development. All source code and features are not production ready.