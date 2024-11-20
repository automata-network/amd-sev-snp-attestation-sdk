// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import {Script, console} from "forge-std/Script.sol";
import {KDS} from "../src/KDS.sol";
import {SEVAgentAttestation} from "../src/SEVAgentAttestation.sol";
import "../src/types/Structs.sol";

contract Configure is Script {
    uint256 privateKey = vm.envUint("PRIVATE_KEY");

    function configureRootPubkey(address kdsAddr, uint8 processorModel, bytes memory e, bytes memory m) public {
        KDS kds = KDS(kdsAddr);
        vm.broadcast(privateKey);
        kds.configureRootPubkey(ProcessorType(processorModel), abi.encode(e, m));
    }

    function configureRiscZero(address sevAddr) public {
        SEVAgentAttestation sev = SEVAgentAttestation(sevAddr);
        address riscZeroVerifier = vm.envAddress("RISCZERO_VERIFIER_ADDR");
        bytes32 sevImageId = vm.envBytes32("SEV_SNP_IMAGE_ID");
        vm.broadcast(privateKey);
        sev.updateRisc0Config(riscZeroVerifier, sevImageId);
    }
}
