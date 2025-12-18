// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import {Script, console} from "forge-std/Script.sol";
import {SP1Verifier} from "@sp1-contracts/v5.0.0/SP1VerifierGroth16.sol";
import {ControlID, RiscZeroGroth16Verifier} from "risc0/groth16/RiscZeroGroth16Verifier.sol";
import {SEVAgentAttestation} from "../src/SEVAgentAttestation.sol";
import {
    ISnpAttestation,
    ZkCoProcessorType,
    ZkCoProcessorConfig,
    ProcessorType
} from "../src/interfaces/ISnpAttestation.sol";
import {LibString} from "solady/utils/LibString.sol";
import {Ownable} from "solady/auth/Ownable.sol";

contract Deploy is Script {
    using LibString for string;
    using LibString for uint256;

    bytes32 constant SEV_SNP_ATTESTATION_SALT = keccak256("SEV_SNP_ATTESTATION_SALT");
    address owner = vm.envAddress("OWNER");

    function readDeployed(string memory key) internal view returns (address) {
        address addr = vm.envOr(key, address(0));
        if (addr != address(0)) {
            console.log(string(abi.encodePacked("read ", key, " from env:")), addr);
            return addr;
        }

        string memory fp = string(abi.encodePacked("deployments/", block.chainid.toString(), ".json"));
        if (vm.exists(fp)) {
            string memory deployment = vm.readFile(fp);
            string memory jsonKey = string(abi.encodePacked(".", key));
            if (vm.keyExistsJson(deployment, jsonKey)) {
                addr = vm.parseJsonAddress(deployment, jsonKey);
                console.log(string(abi.encodePacked("read ", key, " from deployment:")), addr);
                return addr;
            }
        }

        revert(
            string(
                abi.encodePacked(
                    "No deployment found for ", key, " from file or env, chainid:", block.chainid.toString()
                )
            )
        );
    }

    function saveDeployed(string memory key, address addr) internal {
        string memory fp = string(abi.encodePacked("deployments/", block.chainid.toString(), ".json"));
        string memory deployment = "{}";
        if (vm.exists(fp)) {
            deployment = vm.readFile(fp);
            string[] memory keys = vm.parseJsonKeys(deployment, ".");
            for (uint256 i = 0; i < keys.length; i++) {
                if (keys[i].eq("remark")) {
                    continue;
                }
                string memory keyPath = string(abi.encodePacked(".", keys[i]));
                vm.serializeAddress(deployment, keys[i], vm.parseJsonAddress(deployment, keyPath));
            }
        }
        vm.serializeAddress(deployment, key, addr);

        deployment = vm.serializeString(deployment, "remark", "deployments");
        console.log(string(abi.encodePacked("save file ", fp, ": ", deployment)));
        vm.writeFile(fp, deployment);
    }

    function deploySP1Verifier() public {
        vm.startBroadcast();
        SP1Verifier sp1Verifier = new SP1Verifier();
        console.log("SP1Verifier deployed at", address(sp1Verifier));
        saveDeployed("SP1_VERIFIER", address(sp1Verifier));
        vm.stopBroadcast();
    }

    function deployRisc0Verifier() public {
        vm.startBroadcast();
        RiscZeroGroth16Verifier risc0Verifier =
            new RiscZeroGroth16Verifier(ControlID.CONTROL_ROOT, ControlID.BN254_CONTROL_ID);
        console.log("Risc0Verifier deployed at", address(risc0Verifier));
        saveDeployed("RISC0_VERIFIER", address(risc0Verifier));
        vm.stopBroadcast();
    }

    function deployVerifier() public {
        uint256 maxTimeDiff = vm.envOr("MAX_TIME_DIFF", uint256(1000));
        console.log(block.timestamp);
        vm.startBroadcast();
        SEVAgentAttestation verifier =
            new SEVAgentAttestation{salt: SEV_SNP_ATTESTATION_SALT}(owner, uint64(maxTimeDiff), new bytes32[](0));

        vm.stopBroadcast();
        console.log("SEVAgentAttestation deployed at: ", address(verifier));
        saveDeployed("VERIFIER", address(verifier));
    }

    function setRootCert(ProcessorType processor, string memory path) public {
        ISnpAttestation verifier = ISnpAttestation(readDeployed("VERIFIER"));
        bytes memory _rootCert = vm.readFileBinary(path);
        vm.startBroadcast();
        verifier.setRootCert(processor, sha256(_rootCert));
        vm.stopBroadcast();
        console.log("Root certificate set to");
        console.logBytes32(sha256(_rootCert));
    }

    function _getZkType(string memory zktype) internal pure returns (ZkCoProcessorType zkType) {
        if (zktype.eq("Succinct")) {
            zkType = ZkCoProcessorType.Succinct;
        } else if (zktype.eq("RiscZero")) {
            zkType = ZkCoProcessorType.RiscZero;
        } else {
            revert("unknown zkType");
        }
    }

    function setZkVerifier(string memory path) public {
        string memory proofJson = vm.readFile(path);
        bytes32 verifierId = vm.parseJsonBytes32(proofJson, ".program_id.verifier_id");
        string memory zktype = vm.parseJsonString(proofJson, ".zktype");
        ZkCoProcessorType zkType = _getZkType(zktype);
        ZkCoProcessorConfig memory config =
            ZkCoProcessorConfig({latestProgramIdentifier: verifierId, defaultZkVerifier: address(0)});
        if (zkType == ZkCoProcessorType.RiscZero) {
            config.defaultZkVerifier = readDeployed("RISC0_VERIFIER");
        } else if (zkType == ZkCoProcessorType.Succinct) {
            config.defaultZkVerifier = readDeployed("SP1_VERIFIER");
        } else {
            revert("unknown zkType");
        }
        console.log(Ownable(readDeployed("VERIFIER")).owner());
        console.log(msg.sender);
        vm.startBroadcast();
        ISnpAttestation(readDeployed("VERIFIER")).setZkConfiguration(zkType, config);
        vm.stopBroadcast();
    }

    function updateZkVerifiers(string memory sp1Program, string memory risc0Program) public {
        setZkVerifier(sp1Program);
        setZkVerifier(risc0Program);
    }

    function deployAll(string memory sp1Program, string memory risc0Program) public {
        deployVerifier();
        setZkVerifier(sp1Program);
        setZkVerifier(risc0Program);
    }
}
