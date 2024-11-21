// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import {Script, console} from "forge-std/Script.sol";
import {KDS} from "../src/KDS.sol";
import {SEVAgentAttestation} from "../src/SEVAgentAttestation.sol";

contract Deploy is Script {
    uint256 privateKey = vm.envUint("PRIVATE_KEY");

    function deployKDS() public {
        address x509Verifier = vm.envAddress("X509_CHAIN_VERIFIER_ADDR");
        vm.broadcast(privateKey);
        KDS kds = new KDS(x509Verifier);
        console.log("KDS deployed at: ", address(kds));
    }

    function deployAgentAttestation() public {
        vm.broadcast(privateKey);

        address kds = vm.envAddress("KDS_ADDRESS");

        SEVAgentAttestation sev = new SEVAgentAttestation(kds);

        console.log("SEVAgentAttestation deployed at: ", address(sev));
    }
}
