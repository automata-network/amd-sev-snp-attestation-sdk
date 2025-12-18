// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import {Script, console} from "forge-std/Script.sol";
import "../src/SEVAgentAttestation.sol";

contract Configure is Script {
    function configureZk(uint8 zk, address verifierGateway, bytes32 programId) public {
        address attestationAddr = vm.envAddress("AMD_SEV_SNP_ATTESTATION_VERIFIER");

        ZkCoProcessorConfig memory config =
            ZkCoProcessorConfig({latestProgramIdentifier: programId, defaultZkVerifier: verifierGateway});

        vm.broadcast();
        SEVAgentAttestation(attestationAddr).setZkConfiguration(ZkCoProcessorType(zk), config);
    }
}
