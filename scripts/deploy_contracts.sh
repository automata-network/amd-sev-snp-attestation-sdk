#!/bin/bash

set -euo pipefail

function _deploy() {
    cd contracts
    forge script ./script/Deploy.s.sol --broadcast --rpc-url $RPC_URL --private-key $PRIVATE_KEY --sig "$@"
    cd ../
}

function getDeployment() {
    echo $(cat contracts/deployments/$1.json | jq -r .$2)
}

function getProgram() {
    echo $(cat samples/$1_program_id.json | jq -r .program_id.$2)
}

function _printAddr() {
    echo "| $1 | $2    | $(getDeployment $2 VERIFIER)  | $(getDeployment $2 SP1_VERIFIER) | $(getDeployment $2 RISC0_VERIFIER) |"
}

function _summary() {
    echo "| Network | ChainID  | SEVAgentAttestation                        | SP1Verifier                                | RiscZeroGroth16Verifier                    |"
    echo "| ------- | -------- | ------------------------------------------ | ------------------------------------------ | ------------------------------------------ |"
    _printAddr "Holesky" "17000"
    _printAddr "Sepolia" "11155111"
    _printAddr "Hoodi" "560048"

    echo
    echo "| ZkType | Verifier ID | "
    echo "| ------ | ----------- | "
    echo "| Risc0  | $(getProgram risc0 verifier_id) | "
    echo "| SP1    | $(getProgram sp1 verifier_id) |"
}

function run_in_all_network() {
    RPC_URL=$HOLESKY_RPC_URL "$@"
    RPC_URL=$SEPOLIA_RPC_URL "$@"
    RPC_URL=$HOODI_RPC_URL "$@"
}

echo "Holesky: $HOLESKY_RPC_URL"
echo "Sepolia: $SEPOLIA_RPC_URL"
echo "Hoodi: $HOODI_RPC_URL"

cargo build

target/debug/snp-attest-cli upload --risc0 --out samples/risc0_program_id.json
target/debug/snp-attest-cli upload --sp1 --out samples/sp1_program_id.json

#run_in_all_network _deploy 'deployAll(string,string,string)' ../samples/amd_ark.der ../samples/sp1_program_id.json ../samples/risc0_program_id.json
run_in_all_network _deploy 'updateZkVerifiers(string,string)' ../samples/sp1_program_id.json ../samples/risc0_program_id.json

_summary