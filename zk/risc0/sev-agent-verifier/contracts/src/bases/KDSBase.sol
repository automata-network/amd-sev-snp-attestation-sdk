//SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "../utils/X509Helper.sol";
import "../types/Structs.sol";
import {LibString} from "solady/utils/LibString.sol";

/**
 * @title KDS Base Contract
 * @notice This contract provides the basic read and write methods.
 * @dev is expected to extend some methods marked with a VIRTUAL modifier
 * to implement business logic suited to their usecase
 * @notice See {{ KDS.sol }} for RiscZero integration.
 */
abstract contract KDSBase {
    using Asn1Decode for bytes;
    using NodePtr for uint256;
    using BytesUtils for bytes;
    using LibString for string;

    /// VEK Extension OIDs

    // 1.3.6.1.4.1.3704.1.3.1
    bytes constant BOOTLOADER_OID = hex"2B060104019C78010301";
    // 1.3.6.1.4.1.3704.1.3.2
    bytes constant TEE_OID = hex"2B060104019C78010302";
    // 1.3.6.1.4.1.3704.1.3.3
    bytes constant SNP_OID = hex"2B060104019C78010303";
    // 1.3.6.1.4.1.3704.1.3.8
    bytes constant MICROCODE_OID = hex"2B060104019C78010308";
    // 1.3.6.1.4.1.3704.1.4
    bytes constant HWID_OID = hex"2B060104019C780104";

    /// Errors

    // 4cb8d6fb
    error Unknown_Subject_Name();
    // 3fec5d98
    error Unknown_Processor(string processorName);
    // 74ce2fcc
    error Incorrect_Vek_CA_Chain_Length();
    // d549bafe
    error Invalid_Vek_CA_Cert();

    /**
     * @notice ARK Certs, the key is the hash of the Processor type, e.g. keccak256(PROCESSOR_TYPE_ENUM)
     * @notice ASK Certs, the key is the hash of the concatenated Processor and VEK types
     * E.g. keccak256(abi.encodePacked(PROCESSOR_TYPE_ENUM, VEK_TYPE_ENUM))
     * @notice VCEK Certs, the key is the hash of the Processor type and TCB values in the following order:
     * E.g. keccak256(abi.encodePacked(PROCESSOR_TYPE_ENUM, BOOTLOADER_TCB, TEE_TCB, SNP_TCB, MICROCODE_TCB))
     */
    mapping(bytes32 key => bytes cert) _certs;

    mapping(bytes32 key => bytes32 certHash) _certHashes;

    /// @dev certchain array may either contain ASK or ARK individually or both in the order of:
    /// @dev certchain[0] = ASK
    /// @dev certchain[1] = ARK
    /// @dev the length of certchain can never be greater than 2
    /// @dev must implement a proving scheme that can be feasibly verified for certificate upserts
    /// @dev may pass proof data, such as encoded SNARK proofs to the proof param
    /// @dev must extend this method to include proof verification logic
    function upsertVekCaChain(bytes[] calldata certchain, bytes calldata) public virtual {
        if (certchain.length > 2 || certchain.length == 0) {
            revert Incorrect_Vek_CA_Chain_Length();
        }
        for (uint256 i = 0; i < certchain.length;) {
            bytes memory cert = certchain[i];
            (CertType caType, string[] memory caSubjectCnSplit) = _checkVekCaType(cert);
            if (caType == CertType.ARK) {
                ProcessorType processor = _parseArkCn(caSubjectCnSplit);
                _upsertArk(cert, processor);
            } else {
                (ProcessorType processor, CertType vekType) = _parseAskCn(caSubjectCnSplit);
                _upsertAsk(cert, processor, vekType);
            }
            unchecked {
                i++;
            }
        }
    }

    /// @dev must implement a proving scheme that can be feasibly verified for VEK upserts
    /// @dev may pass proof data, such as encoded SNARK proofs to the proof param
    /// @dev must extend this method to include proof verification logic
    function upsertVekCert(bytes calldata vek, bytes calldata) public virtual {
        (ProcessorType processorModel, CertType vekType, TcbVersion memory tcb,) = _parseVek(vek);
        _upsertVek(vek, processorModel, vekType, tcb);
    }

    function fetchCa(ProcessorType processorModel, CertType vekType)
        public
        view
        virtual
        returns (bytes memory ask, bytes memory ark)
    {
        bytes32 askKey = _computeASKKey(processorModel, vekType);
        bytes32 arkKey = _computeARKKey(processorModel);
        ask = _certs[askKey];
        ark = _certs[arkKey];
    }

    function fetchVek(ProcessorType processorModel, CertType vekType, TcbVersion calldata reportedTcb)
        public
        view
        virtual
        returns (bytes memory vek)
    {
        bytes32 vekKey = _computeVEKKey(processorModel, vekType, reportedTcb);
        vek = _certs[vekKey];
    }

    function getARKHash(ProcessorType processorModel) public view virtual returns (bytes32) {
        bytes32 key = _computeARKKey(processorModel);
        return _certHashes[key];
    }

    function getASKHash(ProcessorType processorModel, CertType vekType) public view virtual returns (bytes32) {
        bytes32 key = _computeASKKey(processorModel, vekType);
        return _certHashes[key];
    }

    function getVEKHash(ProcessorType processorModel, CertType vekType, TcbVersion calldata reportedTcb)
        public
        view
        virtual
        returns (bytes32)
    {
        bytes32 key = _computeVEKKey(processorModel, vekType, reportedTcb);
        return _certHashes[key];
    }

    function _computeARKKey(ProcessorType processorModel) internal pure returns (bytes32 arkKey) {
        arkKey = keccak256(abi.encodePacked(processorModel));
    }

    function _computeASKKey(ProcessorType processorModel, CertType vekKey) internal pure returns (bytes32 askKey) {
        require(vekKey == CertType.VCEK || vekKey == CertType.VLEK, "Invalid VEK Cert Type");
        askKey = keccak256(abi.encodePacked(processorModel, vekKey));
    }

    function _computeVEKKey(ProcessorType processorModel, CertType vekType, TcbVersion memory reportedTcb)
        internal
        pure
        returns (bytes32 vekKey)
    {
        vekKey = keccak256(
            abi.encodePacked(
                processorModel, vekType, reportedTcb.bootloader, reportedTcb.tee, reportedTcb.snp, reportedTcb.microcode
            )
        );
    }

    function _checkVekCaType(bytes memory vekCaLeaf)
        internal
        pure
        returns (CertType caType, string[] memory leafSubjectCnSplit)
    {
        string memory leafSubjectCn = X509Helper.getSubjectCommonName(vekCaLeaf);
        leafSubjectCnSplit = leafSubjectCn.split("-");
        bool isArk = leafSubjectCnSplit[0].eq("ARK");
        bool isAsk = leafSubjectCnSplit[0].eq("SEV");
        if (isArk) {
            caType = CertType.ARK;
        } else if (isAsk) {
            caType = CertType.ASK;
        } else {
            revert Invalid_Vek_CA_Cert();
        }
    }

    function _parseArkCn(string[] memory splitSubjectCn) internal pure returns (ProcessorType processorModel) {
        string memory processorName = splitSubjectCn[1];
        processorModel = _parseProcessorModel(processorName);
    }

    function _parseAskCn(string[] memory splitSubjectCn)
        internal
        pure
        returns (ProcessorType processorModel, CertType vekType)
    {
        if (splitSubjectCn[1].eq("VLEK")) {
            vekType = CertType.VLEK;
        } else {
            vekType = CertType.VCEK;
        }

        string memory processorName;
        if (vekType == CertType.VLEK) {
            processorName = splitSubjectCn[2];
        } else {
            processorName = splitSubjectCn[1];
        }

        processorModel = _parseProcessorModel(processorName);
    }

    function _parseVek(bytes calldata vek)
        internal
        pure
        returns (ProcessorType processorModel, CertType vekType, TcbVersion memory tcb, bytes memory hwid)
    {
        X509CertObj memory x509 = X509Helper.parseX509DER(vek);
        string[] memory splitSubjectCn = x509.subjectCommonName.split("-");

        if (!splitSubjectCn[0].eq("SEV")) {
            revert Unknown_Subject_Name();
        }

        if (splitSubjectCn[1].eq("VLEK")) {
            vekType = CertType.VLEK;
        } else if (splitSubjectCn[1].eq("VCEK")) {
            vekType = CertType.VCEK;
        } else {
            revert Unknown_Subject_Name();
        }
        (tcb, hwid) = _parseVekExtension(vek, x509.extensionPtr, vekType);

        string[] memory splitIssuerCn = x509.issuerCommonName.split("-");
        CertType issuerVekType;
        (processorModel, issuerVekType) = _parseAskCn(splitIssuerCn);
        assert(vekType == issuerVekType);
    }

    function _upsertArk(bytes memory ark, ProcessorType processorModel) internal {
        bytes32 key = _computeARKKey(processorModel);
        _certs[key] = ark;
        _certHashes[key] = sha256(ark);
    }

    function _upsertAsk(bytes memory ask, ProcessorType processorModel, CertType vekType) internal {
        bytes32 key = _computeASKKey(processorModel, vekType);
        _certs[key] = ask;
        _certHashes[key] = sha256(ask);
    }

    function _upsertVek(bytes memory vek, ProcessorType processorModel, CertType vekType, TcbVersion memory tcb)
        internal
    {
        bytes32 key = _computeVEKKey(processorModel, vekType, tcb);
        _certs[key] = vek;
        _certHashes[key] = sha256(vek);
    }

    /// === PRIVATE METHODS ===

    struct Flags {
        bool bootloaderFound;
        bool teeFound;
        bool snpFound;
        bool microcodeFound;
        bool hwidFound;
    }

    function _parseVekExtension(bytes memory vek, uint256 extensionPtr, CertType vekType)
        private
        pure
        returns (TcbVersion memory tcb, bytes memory hwid)
    {
        if (vek[extensionPtr.ixs()] != 0xA3) {
            revert("Not an extension");
        }

        uint256 parentPtr = vek.firstChildOf(extensionPtr);
        uint256 childPtr = vek.firstChildOf(parentPtr);

        // moving flags to memory to avoid stack too deep
        Flags memory flags;

        while (childPtr.ixl() < parentPtr.ixl()) {
            uint256 oidPtr = vek.firstChildOf(childPtr);
            bytes memory oid = vek.bytesAt(oidPtr);
            oidPtr = vek.nextSiblingOf(oidPtr);
            bytes memory octetVal = vek.bytesAt(oidPtr);

            if (BytesUtils.compareBytes(oid, BOOTLOADER_OID)) {
                tcb.bootloader = uint8(bytes1(octetVal.substring(4, 1)));
                flags.bootloaderFound = true;
            } else if (BytesUtils.compareBytes(oid, TEE_OID)) {
                tcb.tee = uint8(bytes1(octetVal.substring(4, 1)));
                flags.teeFound = true;
            } else if (BytesUtils.compareBytes(oid, SNP_OID)) {
                tcb.snp = uint8(bytes1(octetVal.substring(4, 1)));
                flags.snpFound = true;
            } else if (BytesUtils.compareBytes(oid, MICROCODE_OID)) {
                tcb.microcode = uint8(bytes1(octetVal.substring(4, 1)));
                flags.microcodeFound = true;
            } else if (vekType == CertType.VCEK && BytesUtils.compareBytes(oid, HWID_OID)) {
                // present only in VCEK certs
                hwid = octetVal;
                flags.hwidFound = true;
            }

            if (
                flags.bootloaderFound && flags.teeFound && flags.snpFound && flags.microcodeFound
                    && (vekType == CertType.VLEK || flags.hwidFound)
            ) {
                break;
            }

            childPtr = vek.nextSiblingOf(childPtr);
        }
    }

    function _parseProcessorModel(string memory processorString) private pure returns (ProcessorType processor) {
        if (processorString.eq("Milan")) {
            processor = ProcessorType.Milan;
        } else if (processorString.eq("Genoa")) {
            processor = ProcessorType.Genoa;
        } else if (processorString.eq("Bergamo")) {
            processor = ProcessorType.Bergamo;
        } else if (processorString.eq("Siena")) {
            processor = ProcessorType.Siena;
        } else {
            revert Unknown_Processor(processorString);
        }
    }
}
