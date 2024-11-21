// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import {Script, console} from "forge-std/Script.sol";
import {KDS} from "../src/KDS.sol";
import "../src/SEVAgentAttestation.sol";
import "../src/types/Structs.sol";

contract Configure is Script {
    uint256 privateKey = vm.envUint("PRIVATE_KEY");

    function configureRootPubkey(address kdsAddr, uint8 processorModel, bytes memory e, bytes memory m) public {
        KDS kds = KDS(kdsAddr);
        vm.broadcast(privateKey);
        kds.configureRootPubkey(ProcessorType(processorModel), abi.encode(e, m));
    }

    function configureZk(uint8 zk, address verifierGateway, bytes32 programId) public {
        address attestationAddr = vm.envAddress("AMD_SEV_SNP_ATTESTATION_VERIFIER");

        ZkCoProcessorConfig memory config =
            ZkCoProcessorConfig({programIdentifier: programId, zkVerifier: verifierGateway});

        vm.broadcast(privateKey);
        SEVAgentAttestation(attestationAddr).setZkConfiguration(ZkCoProcessorType(zk), config);
    }
}
