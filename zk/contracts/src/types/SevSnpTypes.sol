//SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {BytesUtils} from "../utils/BytesUtils.sol";

enum ProcessorType {
    // 7003 series AMD EPYC Processor
    Milan,
    // 9004 series AMD EPYC Processor
    Genoa,
    // 97x4 series AMD EPYC Processor
    Bergamo,
    // 8004 series AMD EPYC Processor
    Siena
}

enum CertType {
    // Versioned Chip Endorsement Key
    VCEK,
    // Versioned Loaded Endorsement Key
    VLEK,
    // AMD SEV Signing Key
    ASK,
    // AMD Root Signing Key
    ARK
}

struct TcbVersion {
    uint8 bootloader;
    uint8 tee;
    uint8 snp;
    uint8 microcode;
}

uint256 constant TCB_VERSION_SIZE = 8; // BYTES

struct AttestationReport {
    uint32 version;
    uint32 guestSvn;
    bytes8 guestPolicyRaw;
    bytes16 familyId;
    bytes16 imageId;
    uint32 vmpl;
    uint32 sigAlgo;
    TcbVersion currentTcb;
    bytes8 platInfoRaw;
    uint32 authorKeyEn;
    uint32 reserved0;
    bytes reportData; // 64 bytes
    bytes measurement; // 48 bytes
    bytes32 hostData;
    bytes idKeyDigest; // 48 bytes
    bytes authorKeyDigest; // 48 bytes
    bytes32 reportId;
    bytes32 reportIdMd;
    TcbVersion reportedTcb;
    bytes24 reserved1;
    bytes chipId; // 64 bytes
    TcbVersion committedTcb;
    uint8 currentBuild;
    uint8 currentMinor;
    uint8 currentMajor;
    uint8 reserved2;
    uint8 committedBuild;
    uint8 committedMinor;
    uint8 committedMajor;
    uint8 reserved3;
    TcbVersion launchTcb;
    bytes reserved_4; // 168 bytes
    bytes rawSignature;
}

library TcbVersionLib {
    using BytesUtils for bytes;

    function parseTcbVersion(bytes memory rawTcb) internal pure returns (TcbVersion memory tcb) {
        tcb = TcbVersion({
            bootloader: rawTcb.readUint8(0),
            tee: rawTcb.readUint8(1),
            snp: rawTcb.readUint8(6),
            microcode: rawTcb.readUint8(7)
        });
    }
}

library AttestationReportLib {
    using BytesUtils for bytes;

    /// @notice Attestation Report Serialization can be found in Table 22 of the manual
    /// @notice https://www.amd.com/content/dam/amd/en/documents/epyc-technical-docs/specifications/56860.pdf
    function deserializeRawAttestationReport(bytes memory attestatonReportRaw)
        internal
        pure
        returns (AttestationReport memory report)
    {
        // TODO
    }

    /// @notice extract the reported tcb values from the report without parsing the entire data
    function getReportedTcb(bytes memory attestationReportRaw) internal pure returns (TcbVersion memory reportedTcb) {
        uint256 offset = 0x0180;
        reportedTcb = TcbVersionLib.parseTcbVersion(attestationReportRaw.substring(offset, TCB_VERSION_SIZE));
    }

    /// @notice determine the signing VEK type from the report without parsing the entire data
    function getVEKType(bytes memory attestationReportRaw) internal pure returns (CertType vekType) {
        uint256 offset = 0x48;
        bytes4 author_key_en = bytes4(attestationReportRaw.substring(offset, 4));
        bytes1 bits = author_key_en[0];
        bytes1 signerType = bits & 0x1c;
        if (signerType == 0x0) {
            vekType = CertType.VCEK;
        } else if (signerType == 0x04) {
            vekType = CertType.VLEK;
        } else {
            revert("Unknown VEK type");
        }
    }
}
