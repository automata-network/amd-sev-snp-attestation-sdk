//SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IRiscZeroVerifier} from "risc0/IRiscZeroVerifier.sol";
import {KDSBase} from "./bases/KDSBase.sol";
import {Ownable} from "solady/auth/Ownable.sol";

import "./types/Structs.sol";

contract SEVAgentAttestation is Ownable {
    /// @notice RISC Zero verifier contract address
    IRiscZeroVerifier public riscZeroVerifier;

    /// @notice AMD Key Distribution Service contract address
    KDSBase public kds;

    /// @notice The ImageID of the Risc0 SEV Attestation Guest ELF
    bytes32 public SEV_RISC0_IMAGE_ID;

    constructor(address risc0Verifier, bytes32 imageId, address kdsAddr) {
        _initializeOwner(msg.sender);
        riscZeroVerifier = IRiscZeroVerifier(risc0Verifier);
        SEV_RISC0_IMAGE_ID = imageId;
        kds = KDSBase(kdsAddr);
    }

    // 5f8daf95
    error Unknown_Pcr10_Hash_Algo(uint16 hashAlgo);
    // 21e22626
    error Invalid_Certchain_Length();
    // ab20140d
    error Root_Of_Trust_Mismatch();

    function updateRisc0Config(address risc0Verifier, bytes32 imageId) external onlyOwner {
        riscZeroVerifier = IRiscZeroVerifier(risc0Verifier);
        SEV_RISC0_IMAGE_ID = imageId;
    }

    function updateKds(address kdsAddr) external onlyOwner {
        kds = KDSBase(kdsAddr);
    }

    function verifyAndAttestWithZKProof(bytes calldata journal, bytes calldata seal)
        external
        view
        returns (Journal memory parsed)
    {
        riscZeroVerifier.verify(seal, SEV_RISC0_IMAGE_ID, sha256(journal));

        // Step 1: Parse the Journal
        parsed = _deserializeJournal(journal);

        // Step 2: Verify the root of trust for SEV SNP Attestation
        bytes32 arkHash = parsed.vekRootHash;
        bytes32 expectedAskHash = kds.getARKHash(parsed.processorModel);
        if (expectedAskHash != arkHash) {
            revert Root_Of_Trust_Mismatch();
        }

        // STEP 3 TODO: Verify the root of trust for TPM Quote with AIK, or optionally, EK
    }

    function _deserializeJournal(bytes calldata journal) private pure returns (Journal memory parsed) {
        parsed.apiOpt = ApiOpt(uint8(bytes1(journal[0:1])));

        parsed.processorModel = ProcessorType(uint8(bytes1(journal[1:2])));

        uint32 sevLength = uint32(bytes4(journal[2:6]));
        uint256 offset = 6;

        parsed.rawSevAttestationReport = journal[offset:offset + sevLength];
        offset += sevLength;

        parsed.vekRootHash = bytes32(journal[offset:offset + 32]);
        offset += 32;

        if (parsed.apiOpt == ApiOpt.SEV_TPM) {
            uint32 tpmQuoteLen = uint32(bytes4(journal[offset:offset + 4]));
            offset += 4;

            parsed.rawTpmQuote = journal[offset:offset + tpmQuoteLen];
            offset += tpmQuoteLen;

            parsed.pcr10HashAlgo = uint16(bytes2(journal[offset:offset + 2]));
            offset += 2;

            uint256 pcr10Len;
            if (parsed.pcr10HashAlgo == TPM_ALG_SHA1) {
                pcr10Len = 20;
            } else if (parsed.pcr10HashAlgo == TPM_ALG_SHA256) {
                pcr10Len = 32;
            } else {
                revert Unknown_Pcr10_Hash_Algo(parsed.pcr10HashAlgo);
            }
            parsed.pcr10Value = journal[offset:offset + pcr10Len];
            offset += pcr10Len;

            parsed.tpmAikRootHash = bytes32(journal[offset:offset + 32]);
            offset += 32;

            if (offset < journal.length) {
                parsed.tpmEkRootHash = bytes32(journal[offset:offset + 32]);
                offset += 32;
            }
        }

        assert(journal.length == offset);
    }
}
