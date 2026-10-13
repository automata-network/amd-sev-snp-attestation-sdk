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

contract Deploy is Script {
    using LibString for string;
    using LibString for uint256;

    bytes32 constant SEV_SNP_ATTESTATION_SALT = keccak256("SEV_SNP_ATTESTATION_SALT");

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

    function deploySP1Verifier() public targetChainOnly {
        vm.startBroadcast(_sender());
        SP1Verifier sp1Verifier = new SP1Verifier();
        console.log("SP1Verifier deployed at", address(sp1Verifier));
        saveDeployed("SP1_VERIFIER", address(sp1Verifier));
        vm.stopBroadcast();
    }

    function deployRisc0Verifier() public targetChainOnly {
        vm.startBroadcast(_sender());
        RiscZeroGroth16Verifier risc0Verifier =
            new RiscZeroGroth16Verifier(ControlID.CONTROL_ROOT, ControlID.BN254_CONTROL_ID);
        console.log("Risc0Verifier deployed at", address(risc0Verifier));
        saveDeployed("RISC0_VERIFIER", address(risc0Verifier));
        vm.stopBroadcast();
    }

    function deployVerifier() public targetChainOnly {
        uint256 maxTimeDiff = vm.envOr("MAX_TIME_DIFF", uint256(1000));
        require(maxTimeDiff <= type(uint64).max, "TIME_WINDOW_OVERFLOW");
        SEVAgentAttestation verifier = deploy(vm.envAddress("OWNER"), uint64(maxTimeDiff));
        saveDeployed("VERIFIER", address(verifier));
    }

    function setRootCert(ProcessorType processor, string memory path) public targetChainOnly {
        SEVAgentAttestation verifier = _owned(readDeployed("VERIFIER"));
        bytes memory _rootCert = vm.readFileBinary(path);
        require(_rootCert.length != 0, "EMPTY_ROOT_CERT");
        vm.startBroadcast(_sender());
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

    function setZkVerifier(string memory path) public targetChainOnly {
        SEVAgentAttestation target = _owned(readDeployed("VERIFIER"));
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
        _program(verifierId);
        require(config.defaultZkVerifier.code.length > 0, "BACKEND_HAS_NO_CODE");
        vm.startBroadcast(_sender());
        target.setZkConfiguration(zkType, config);
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
    modifier targetChainOnly() {
        require(block.chainid == vm.envUint("EXPECTED_CHAIN_ID"), "UNEXPECTED_CHAIN");
        _;
    }

    function deploy(address owner, uint64 maxTimeDiff) public targetChainOnly returns (SEVAgentAttestation target) {
        require(owner != address(0), "ZERO_OWNER");
        require(maxTimeDiff != 0, "ZERO_TIME_WINDOW");
        vm.startBroadcast(_sender());
        target = new SEVAgentAttestation{salt: SEV_SNP_ATTESTATION_SALT}(owner, maxTimeDiff);
        vm.stopBroadcast();
        require(target.owner() == owner && target.maxTimeDiff() == maxTimeDiff, "DEPLOYMENT_CHECK_FAILED");
        console.log("SEVAgentAttestation", address(target));
    }

    /// @notice Bootstrap a fresh SP1 configuration for Milan and Genoa.
    /// @dev Root arguments are SHA256 of trusted ARK DER, not certificate-path prefix hashes.
    /// Backend must be independently verified against a real proof of the chosen version/type.
    function configure(
        address targetAddress,
        address sp1Verifier,
        bytes32 programVKey,
        bytes32 milanArk,
        bytes32 genoaArk
    ) external targetChainOnly {
        SEVAgentAttestation target = _owned(targetAddress);
        _program(programVKey);
        require(sp1Verifier.code.length > 0, "BACKEND_HAS_NO_CODE");
        require(milanArk != 0 && genoaArk != 0, "ZERO_ARK_HASH");
        require(target.programIdentifiers(ZkCoProcessorType.Succinct).length == 0, "SP1_ALREADY_CONFIGURED");
        vm.startBroadcast(_sender());
        target.setRootCert(ProcessorType.Milan, milanArk);
        target.setRootCert(ProcessorType.Genoa, genoaArk);
        target.setZkConfiguration(ZkCoProcessorType.Succinct, ZkCoProcessorConfig(programVKey, sp1Verifier));
        vm.stopBroadcast();
        require(target.rootCerts(ProcessorType.Milan) == milanArk, "MILAN_ROOT_MISMATCH");
        require(target.rootCerts(ProcessorType.Genoa) == genoaArk, "GENOA_ROOT_MISMATCH");
        require(target.zkVerifier(ZkCoProcessorType.Succinct) == sp1Verifier, "BACKEND_MISMATCH");
        require(target.programIdentifier(ZkCoProcessorType.Succinct) == programVKey, "PROGRAM_MISMATCH");
    }

    /// @notice Adds a program to the allowlist AND makes it latest. Existing entries remain allowed.
    function addProgram(address targetAddress, bytes32 programVKey) external targetChainOnly {
        SEVAgentAttestation target = _owned(targetAddress);
        _program(programVKey);
        require(target.zkVerifier(ZkCoProcessorType.Succinct).code.length > 0, "BACKEND_HAS_NO_CODE");
        vm.startBroadcast(_sender());
        target.updateProgramIdentifier(ZkCoProcessorType.Succinct, programVKey);
        vm.stopBroadcast();
        require(target.programIdentifier(ZkCoProcessorType.Succinct) == programVKey, "PROGRAM_MISMATCH");
    }

    /// @notice Removes an old allowed program. The contract rejects removing the latest program.
    function removeProgram(address targetAddress, bytes32 programVKey) external targetChainOnly {
        SEVAgentAttestation target = _owned(targetAddress);
        _program(programVKey);
        vm.startBroadcast(_sender());
        target.removeProgramIdentifier(ZkCoProcessorType.Succinct, programVKey);
        vm.stopBroadcast();
    }

    function _owned(address targetAddress) private view returns (SEVAgentAttestation target) {
        require(targetAddress.code.length > 0, "TARGET_HAS_NO_CODE");
        target = SEVAgentAttestation(targetAddress);
        require(target.owner() == _sender(), "SENDER_NOT_OWNER");
    }

    function _sender() private view returns (address sender) {
        sender = vm.envAddress("SENDER");
        require(sender != address(0), "ZERO_SENDER");
    }

    function _program(bytes32 programVKey) private pure {
        require(programVKey != 0, "ZERO_PROGRAM_VKEY");
    }
}
