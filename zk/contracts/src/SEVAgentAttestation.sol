//SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// ZK-Coprocessor imports:
import {IRiscZeroVerifier} from "risc0/IRiscZeroVerifier.sol";
import {ISP1Verifier} from "@sp1-contracts/ISP1Verifier.sol";

import {KDSBase} from "./bases/KDSBase.sol";
import {Ownable} from "solady/auth/Ownable.sol";

import "./types/Structs.sol";

enum ZkCoProcessorType {
    Unknown,
    RiscZero,
    Succinct
}

/**
 * @title ZK Co-Processor Configuration Object
 * @param programIdentifier - This is the identifier of the ZK Program, required for
 * verification
 * @param zkVerifier - Points to the address of the ZK Verifier contract. Ideally
 * this should be pointing to a universal verifier, that may support multiple proof types and/or versions.
 */
struct ZkCoProcessorConfig {
    bytes32 programIdentifier;
    address zkVerifier;
}

contract SEVAgentAttestation is Ownable {
    /// @notice AMD Key Distribution Service contract address
    KDSBase public kds;

    mapping(ZkCoProcessorType => ZkCoProcessorConfig) _zkConfig;

    constructor(address kdsAddr) {
        _initializeOwner(msg.sender);
        kds = KDSBase(kdsAddr);
    }

    // 5f8daf95
    error Unknown_Pcr10_Hash_Algo(uint16 hashAlgo);
    // 21e22626
    error Invalid_Certchain_Length();
    // ab20140d
    error Root_Of_Trust_Mismatch();
    // 51abd95c
    error Unknown_Zk_Coprocessor();

    /**
     * @notice Sets the ZK Configuration for the given ZK Co-Processor
     */
    function setZkConfiguration(ZkCoProcessorType zkCoProcessor, ZkCoProcessorConfig memory config)
        external
        onlyOwner
    {
        _zkConfig[zkCoProcessor] = config;
    }

    /**
     * @param zkCoProcessorType 1 - RiscZero, 2 - Succinct... etc.
     * @return this is either the IMAGE_ID for RiscZero Guest Program or
     * Succiinct Program Verifying Key
     */
    function programIdentifier(uint8 zkCoProcessorType) external view returns (bytes32) {
        return _zkConfig[ZkCoProcessorType(zkCoProcessorType)].programIdentifier;
    }

    /**
     * @notice get the contract verifier for the provided ZK Co-processor
     */
    function zkVerifier(uint8 zkCoProcessorType) external view returns (address) {
        return _zkConfig[ZkCoProcessorType(zkCoProcessorType)].zkVerifier;
    }

    function updateKds(address kdsAddr) external onlyOwner {
        kds = KDSBase(kdsAddr);
    }

    function verifyAndAttestWithZKProof(
        bytes calldata output,
        ZkCoProcessorType zkCoprocessor,
        bytes calldata proofBytes
    )
        external
        view
        returns (ZkOutput memory parsed)
    {
        ZkCoProcessorConfig memory zkConfig = _zkConfig[zkCoprocessor];

        if (zkCoprocessor == ZkCoProcessorType.RiscZero) {
            IRiscZeroVerifier(zkConfig.zkVerifier).verify(
                proofBytes, zkConfig.programIdentifier, sha256(output)
            );
        } else if (zkCoprocessor == ZkCoProcessorType.Succinct) {
            ISP1Verifier(zkConfig.zkVerifier).verifyProof(zkConfig.programIdentifier, output, proofBytes);
        } else {
            revert Unknown_Zk_Coprocessor();
        }

        // Step 1: Parse the ZkOutput
        parsed = _deserializeZkOutput(output);

        // Step 2: Verify the root of trust for SEV SNP Attestation
        bytes32 arkHash = parsed.vekRootHash;
        bytes32 expectedAskHash = kds.getARKHash(parsed.processorModel);
        if (expectedAskHash != arkHash) {
            revert Root_Of_Trust_Mismatch();
        }

        // STEP 3 TODO: Verify the root of trust for TPM Quote with AIK, or optionally, EK
    }

    function _deserializeZkOutput(bytes calldata output) private pure returns (ZkOutput memory parsed) {
        parsed.apiOpt = ApiOpt(uint8(bytes1(output[0:1])));

        parsed.processorModel = ProcessorType(uint8(bytes1(output[1:2])));

        uint32 sevLength = uint32(bytes4(output[2:6]));
        uint256 offset = 6;

        parsed.rawSevAttestationReport = output[offset:offset + sevLength];
        offset += sevLength;

        parsed.vekRootHash = bytes32(output[offset:offset + 32]);
        offset += 32;

        if (parsed.apiOpt == ApiOpt.SEV_TPM) {
            uint32 tpmQuoteLen = uint32(bytes4(output[offset:offset + 4]));
            offset += 4;

            parsed.rawTpmQuote = output[offset:offset + tpmQuoteLen];
            offset += tpmQuoteLen;

            parsed.pcr10HashAlgo = uint16(bytes2(output[offset:offset + 2]));
            offset += 2;

            uint256 pcr10Len;
            if (parsed.pcr10HashAlgo == TPM_ALG_SHA1) {
                pcr10Len = 20;
            } else if (parsed.pcr10HashAlgo == TPM_ALG_SHA256) {
                pcr10Len = 32;
            } else {
                revert Unknown_Pcr10_Hash_Algo(parsed.pcr10HashAlgo);
            }
            parsed.pcr10Value = output[offset:offset + pcr10Len];
            offset += pcr10Len;

            parsed.tpmAikRootHash = bytes32(output[offset:offset + 32]);
            offset += 32;

            if (offset < output.length) {
                parsed.tpmEkRootHash = bytes32(output[offset:offset + 32]);
                offset += 32;
            }
        }

        assert(output.length == offset);
    }
}
