# AMD SEV-SNP contracts

Run the commands below from `contracts/`. See the root README for [deployment addresses](../README.md#deployment-information) and the [latest SP1 program](../README.md#latest-amd-sp1-program).

## Environment

```bash
export EXPECTED_CHAIN_ID=1  # Hoodi: 560048
export RPC_URL="<target network RPC URL>"
export WALLET_NAME="<Foundry keystore name>"
export SENDER=$(cast wallet address --account "$WALLET_NAME")
export OWNER="$SENDER"
export MAX_TIME_DIFF=1000  # Journal validity window in seconds
export ETHERSCAN_API_KEY="<Etherscan API key>"
export SP1_VERIFIER="<SP1 verifier address from the root README>"
export PROGRAM_VKEY="<vk_bytes from the root README>"
export MILAN_ARK_SHA256=0x69d063b45344d26a2e94e1f4210de49ef555308287d4c174445c95639a540bcd
export GENOA_ARK_SHA256=0x4c6598d19c18719c5dfd4a7d335f674e5bfe1d8f800cea2cf270c10d103db2f1
```

`WALLET_NAME` is a keystore name; `SENDER` and `OWNER` are addresses. Adjust `MAX_TIME_DIFF` for proving and transaction latency. The program allowlist uses `vk_bytes`, not the remote prover's `vk_hash`.

The root hashes are SHA256 hashes of individual ARK certificates in DER format. AMD publishes the certificate chains for [Milan](https://kdsintf.amd.com/vcek/v1/Milan/cert_chain) and [Genoa](https://kdsintf.amd.com/vcek/v1/Genoa/cert_chain).

## Deploy

```bash
forge script script/Deploy.s.sol:Deploy \
  --rpc-url "$RPC_URL" --chain "$EXPECTED_CHAIN_ID" \
  --sender "$SENDER" --account "$WALLET_NAME" \
  --sig 'deploy(address,uint64)' "$OWNER" "$MAX_TIME_DIFF" \
  --broadcast --verify --verifier etherscan

export VERIFIER="<deployed AMD contract address>"
```

This deploys the AMD contract and verifies its source on Etherscan. Configure roots and SP1 afterward. To simulate deployment only, omit `--broadcast --verify --verifier etherscan`.

## First configuration

Use the current owner's wallet for this and subsequent configuration commands.

```bash
forge script script/Deploy.s.sol:Deploy \
  --rpc-url "$RPC_URL" --sender "$SENDER" --account "$WALLET_NAME" \
  --sig 'configure(address,address,bytes32,bytes32,bytes32)' \
  "$VERIFIER" "$SP1_VERIFIER" "$PROGRAM_VKEY" "$MILAN_ARK_SHA256" "$GENOA_ARK_SHA256" \
  --broadcast
```

`configure` requires an empty SP1 allowlist and sends three transactions to set both roots and register SP1. If interrupted, check which transactions completed before retrying. For an already configured contract, use the program commands below. Omit `--broadcast` to simulate configuration or program changes.

## Add or remove allowed programs

Adding a program makes it **latest** and keeps existing programs allowed. You cannot remove the latest program; select a replacement first.

```bash
export NEW_PROGRAM_VKEY="<new program vk_bytes>"
forge script script/Deploy.s.sol:Deploy \
  --rpc-url "$RPC_URL" --sender "$SENDER" --account "$WALLET_NAME" \
  --sig 'addProgram(address,bytes32)' "$VERIFIER" "$NEW_PROGRAM_VKEY" \
  --broadcast

export OLD_PROGRAM_VKEY="<non-latest program vk_bytes>"
forge script script/Deploy.s.sol:Deploy \
  --rpc-url "$RPC_URL" --sender "$SENDER" --account "$WALLET_NAME" \
  --sig 'removeProgram(address,bytes32)' "$VERIFIER" "$OLD_PROGRAM_VKEY" \
  --broadcast
```
