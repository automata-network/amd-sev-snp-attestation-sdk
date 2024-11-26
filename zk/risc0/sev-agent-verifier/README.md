# Automata AMD SEV-SNP RISC0 Verifier Project

## Quick Start

First, make sure `rustup` is installed. The
`rust-toolchain.toml` file will be used by `cargo` to
automatically install the correct version.

To run an example [test case](./host/src//lib.rs), insert the following command:

```bash
RISC0_DEV_MODE=true cargo test
```

## Running proofs remotely on Bonsai

_Note: The Bonsai proving service is still in early Alpha; an API key is
required for access. [Click here to request access](https://bonsai.xyz/apply)._

If you have access to the URL and API key to Bonsai you can run your proofs
remotely. To prove in Bonsai mode, invoke `cargo run` with two additional
environment variables:

```bash
BONSAI_API_KEY="YOUR_API_KEY" BONSAI_API_URL="BONSAI_URL" cargo run
```

## Use the Demo CLI

### Step 0: Build

```bash
cargo build --release
```

### Step 1: Store the Attestation Report in the `../data` directory

### Step 2: Export the Bonsai Environmental Variables in your shell

```bash
export BONSAI_API_KEY="<api-key>"
export BONSAI_API_URL="https://api.bonsai.xyz"
```

### Step 3: At this point, make sure you are on the `sev-agent-verifier` directory.

### Step 4: Insert the following command, to verify the attestation report.

```bash
RUST_LOG="info" ./target/release/demo verify -o <path-to-the-attestation-report-output-file> -w <your-wallet-key>
```

_Note: Wallet key is optional. If left blank, a staticcall will be performed instead and you will not be able to see the transaction on the explorer.

### Step 5: Pass the `--help` flag, to see available command.

```bash
./target/release/demo verify --help
```
You should see the following output:

```bash
Usage: demo verify [OPTIONS] --output <AGENT_OUTPUT_PATH>

Options:
  -o, --output <AGENT_OUTPUT_PATH>
          The path of the output JSON file fetched from the Agent Service

  -p, --prove-option <PROVE_OPTION>
          Select a proof option. Defaults to Groth16, with the assumption that the Guest program is running on Bonsai
          
          [default: groth16]

          Possible values:
          - default: Generates the default STARK receipt
          - groth16: Generates a Groth16 Receipt. Note: May fail when attempting to generate Groth16 receipt locally on Apple Silicon machines

      --rpc <RPC_URL>
          Chain RPC URL
          
          [default: https://1rpc.io/ata/testnet]

      --verifier_address <VERIFIER_ADDRESS>
          The address of SEVAgentVerifier contract. This is where proofs are verified on-chain
          
          [default: 0xDe510E1F9258c94c5520B717210a301Cc8297F1F]

  -w, --wallet-key <WALLET_KEY>
          Optional: For users intend to explicitly submit a transaction for verification. If left blank, a static call is made instead

  -h, --help
          Print help (see a summary with '-h')

```