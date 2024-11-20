// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Asn1Decode, NodePtr} from "./Asn1Decode.sol";
import {BytesUtils} from "./BytesUtils.sol";
import {DateTimeUtils} from "./DateTimeUtils.sol";

// Diverged from https://github.com/automata-network/automata-on-chain-pccs/blob/main/src/helper/X509Helper.sol

enum PublicKeyAlgorithm {
    UNSUPPORTED,
    EC256,
    EC384,
    RSA
}

enum SignatureAlgorithm {
    UNSUPPORTED,
    SHA256WithECDSA,
    SHA384WithECDSA,
    SHA256WithRSA
}

/**
 * @title Solidity Structure representing X509 Certificates
 * @notice This is a simplified structure of a DER-decoded X509 Certificate
 * @dev The Extension sequence is a custom ASN.1 Sequence that needs to be
 * @dev parsed further in a more specialized contract.
 * @dev IMPORTANT! Post-processing of the public key and signature bytes may be necesary
 */
struct X509CertObj {
    uint256 serialNumber;
    string issuerCommonName;
    uint256 validityNotBefore;
    uint256 validityNotAfter;
    string subjectCommonName;
    bytes subjectPublicKey;
    // for signature verification in the cert chain
    PublicKeyAlgorithm subjectPublicKeyAlgo;
    SignatureAlgorithm issuerSigAlgo;
    /// @dev if the signature is generated with ECDSA
    /// this is the abi.encoded tuple of (r,s)
    /// @dev when parsing abi.encoded tuple (r,s)
    /// it is the responsibility of the implementation contract
    /// to verify the correct length of signatures
    /// e.g. 64 bytes for P256 vs 96 bytes for P384
    bytes signature;
    bytes tbs;
    // the extension needs to be parsed further
    uint256 extensionPtr;
}

/**
 * @title X509 Certificates Library
 * @notice This library can be integrated by smart contracts to parse DER-encoded X509 certificates.
 */
library X509Helper {
    using Asn1Decode for bytes;
    using NodePtr for uint256;
    using BytesUtils for bytes;

    /// ============== Certificate Attributes OIDs ==============

    // 2.5.4.3
    bytes constant COMMON_NAME_OID = hex"550403";

    /// ============== PublicKeyAlgorithm OIDs ==============

    // 1.2.840.10045.2.1
    bytes constant EC_KEY_OID = hex"2A8648CE3D0201";
    // 1.2.840.10045.3.1.7
    bytes constant EC256_KEY_PARAM_OID = hex"2A8648CE3D030107";
    // 1.3.132.0.34
    bytes constant EC384_KEY_PARAM_OID = hex"2B81040022";
    // 1.2.840.113549.1.1.1 (no params)
    bytes constant RSA_KEY_OID = hex"2A864886F70D010101";

    /// ============== SignatureAlgorithm OIDs ==============

    // 1.2.840.10045.4.3.2
    bytes constant SHA256_ECDSA_OID = hex"2A8648CE3D040302";
    // 1.2.840.10045.4.3.3
    bytes constant SHA384_ECDSA_OID = hex"2A8648CE3D040303";
    // 1.2.840.113549.1.1.11
    bytes constant SHA256_RSA_OID = hex"2A864886F70D01010B";

    /// ============== Signature lengths ==============
    uint256 public constant P256_PUBKEY_LEN_BYTES = 64;
    uint256 public constant P384_PUBKEY_LEN_BYTES = 96;

    /// =================================================================================
    /// USE THE GETTERS BELOW IF YOU DON'T WANT TO PARSE THE ENTIRE X509 CERTIFICATE
    /// =================================================================================

    function getTbsAndSigInfo(bytes memory der)
        internal
        pure
        returns (bytes memory tbs, SignatureAlgorithm issuerSigAlgo, bytes memory sig)
    {
        uint256 root = der.root();
        uint256 tbsParentPtr = der.firstChildOf(root);
        uint256 sigPtr = der.nextSiblingOf(tbsParentPtr);

        tbs = der.allBytesAt(tbsParentPtr);
        (issuerSigAlgo, sig) = _getSignatureInfo(der, sigPtr);
    }

    function getSerialNumber(bytes memory der) internal pure returns (uint256 serialNum) {
        uint256 root = der.root();
        uint256 tbsParentPtr = der.firstChildOf(root);
        uint256 tbsPtr = der.firstChildOf(tbsParentPtr);
        tbsPtr = der.nextSiblingOf(tbsPtr);
        serialNum = _parseSerialNumber(der.bytesAt(tbsPtr));
    }

    function getIssuerCommonName(bytes memory der) internal pure returns (string memory issuerCommonName) {
        uint256 root = der.root();
        uint256 tbsParentPtr = der.firstChildOf(root);
        uint256 tbsPtr = der.firstChildOf(tbsParentPtr);
        tbsPtr = der.nextSiblingOf(tbsPtr);
        tbsPtr = der.nextSiblingOf(tbsPtr);
        tbsPtr = der.nextSiblingOf(tbsPtr);
        issuerCommonName = _getCommonName(der, tbsPtr);
    }

    function certIsNotExpired(bytes memory der) internal view returns (bool isValid) {
        uint256 root = der.root();
        uint256 tbsParentPtr = der.firstChildOf(root);
        uint256 tbsPtr = der.firstChildOf(tbsParentPtr);
        tbsPtr = der.nextSiblingOf(tbsPtr);
        tbsPtr = der.nextSiblingOf(tbsPtr);
        tbsPtr = der.nextSiblingOf(tbsPtr);
        tbsPtr = der.nextSiblingOf(tbsPtr);
        (uint256 validityNotBefore, uint256 validityNotAfter) = _getValidity(der, tbsPtr);
        isValid = block.timestamp > validityNotBefore && block.timestamp < validityNotAfter;
    }

    function getSubjectCommonName(bytes memory der) internal pure returns (string memory subjectCommonName) {
        uint256 root = der.root();
        uint256 tbsParentPtr = der.firstChildOf(root);
        uint256 tbsPtr = der.firstChildOf(tbsParentPtr);
        tbsPtr = der.nextSiblingOf(tbsPtr);
        tbsPtr = der.nextSiblingOf(tbsPtr);
        tbsPtr = der.nextSiblingOf(tbsPtr);
        tbsPtr = der.nextSiblingOf(tbsPtr);
        tbsPtr = der.nextSiblingOf(tbsPtr);
        subjectCommonName = _getCommonName(der, tbsPtr);
    }

    function getSubjectPublicKeyInfo(bytes memory der)
        internal
        pure
        returns (PublicKeyAlgorithm subjectPublicKeyAlgo, bytes memory pubKey)
    {
        uint256 root = der.root();
        uint256 tbsParentPtr = der.firstChildOf(root);
        uint256 tbsPtr = der.firstChildOf(tbsParentPtr);
        tbsPtr = der.nextSiblingOf(tbsPtr);
        tbsPtr = der.nextSiblingOf(tbsPtr);
        tbsPtr = der.nextSiblingOf(tbsPtr);
        tbsPtr = der.nextSiblingOf(tbsPtr);
        tbsPtr = der.nextSiblingOf(tbsPtr);
        tbsPtr = der.nextSiblingOf(tbsPtr);
        (subjectPublicKeyAlgo, pubKey) = _getSubjectPublicKeyInfo(der, der.firstChildOf(tbsPtr));
    }

    /// x509 Certificates generally contain a sequence of elements in the following order:
    /// 1. tbs
    /// - 1a. version
    /// - 1b. serial number
    /// - 1c. siganture algorithm
    /// - 1d. issuer
    /// - - 1d(a). common name
    /// - - 1d(b). organization name
    /// - - 1d(c). locality name
    /// - - 1d(d). state or province name
    /// - - 1d(e). country name
    /// - 1e. validity
    /// - - 1e(a) notBefore
    /// - - 1e(b) notAfter
    /// - 1f. subject
    /// - - contains the same set of elements as 1d
    /// - 1g. subject public key info
    /// - - 1g(a). algorithm
    /// - - 1g(b). subject public key
    /// - 1h. Extensions
    /// 2. Signature Algorithm
    /// 3. Signature
    /// - 3a. X value
    /// - 3b. Y value
    function parseX509DER(bytes memory der) internal pure returns (X509CertObj memory cert) {
        uint256 root = der.root();

        uint256 tbsParentPtr = der.firstChildOf(root);
        cert.tbs = der.allBytesAt(tbsParentPtr);

        uint256 tbsPtr = der.firstChildOf(tbsParentPtr);

        tbsPtr = der.nextSiblingOf(tbsPtr);

        cert.serialNumber = _parseSerialNumber(der.bytesAt(tbsPtr));

        tbsPtr = der.nextSiblingOf(tbsPtr);
        tbsPtr = der.nextSiblingOf(tbsPtr);

        cert.issuerCommonName = _getCommonName(der, tbsPtr);

        tbsPtr = der.nextSiblingOf(tbsPtr);
        (cert.validityNotBefore, cert.validityNotAfter) = _getValidity(der, tbsPtr);

        tbsPtr = der.nextSiblingOf(tbsPtr);

        cert.subjectCommonName = _getCommonName(der, tbsPtr);

        tbsPtr = der.nextSiblingOf(tbsPtr);
        (cert.subjectPublicKeyAlgo, cert.subjectPublicKey) = _getSubjectPublicKeyInfo(der, der.firstChildOf(tbsPtr));

        cert.extensionPtr = der.nextSiblingOf(tbsPtr);

        // tbs iteration completed
        // now we just need to look for the signature

        uint256 sigPtr = der.nextSiblingOf(tbsParentPtr);
        (cert.issuerSigAlgo, cert.signature) = _getSignatureInfo(der, sigPtr);
    }

    function _getCommonName(bytes memory der, uint256 commonNameParentPtr)
        private
        pure
        returns (string memory commonName)
    {
        uint256 ptr = der.firstChildOf(commonNameParentPtr);
        while (ptr != 0) {
            uint256 internalPtr = der.firstChildOf(ptr);
            internalPtr = der.firstChildOf(internalPtr);
            if (der.bytesAt(internalPtr).equals(COMMON_NAME_OID)) {
                internalPtr = der.nextSiblingOf(internalPtr);
                commonName = string(der.bytesAt(internalPtr));
                ptr = 0; // equivalent to break
            } else {
                if (ptr.ixl() < commonNameParentPtr.ixl()) {
                    ptr = der.nextSiblingOf(ptr);
                } else {
                    ptr = 0;
                }
            }
        }
    }

    function _getValidity(bytes memory der, uint256 validityPtr)
        private
        pure
        returns (uint256 notBefore, uint256 notAfter)
    {
        uint256 notBeforePtr = der.firstChildOf(validityPtr);
        uint256 notAfterPtr = der.nextSiblingOf(notBeforePtr);
        notBefore = DateTimeUtils.fromDERToTimestamp(der.bytesAt(notBeforePtr));
        notAfter = DateTimeUtils.fromDERToTimestamp(der.bytesAt(notAfterPtr));
    }

    /// @dev RSA public key is returned as an abi-encoded bytes tuple (exponent, modulus)
    /// @dev EC public key is returned as the bitstring as it is
    function _getSubjectPublicKeyInfo(bytes memory der, uint256 subjectPublicKeyInfoPtr)
        private
        pure
        returns (PublicKeyAlgorithm subjectPublicKeyAlgo, bytes memory pubKey)
    {
        uint256 subjectPublicKeyAlgoPtr = der.firstChildOf(subjectPublicKeyInfoPtr);
        bytes memory oid = der.bytesAt(subjectPublicKeyAlgoPtr);
        if (oid.equals(EC_KEY_OID)) {
            subjectPublicKeyAlgoPtr = der.nextSiblingOf(subjectPublicKeyAlgoPtr);
            oid = der.bytesAt(subjectPublicKeyAlgoPtr);
            if (oid.equals(EC256_KEY_PARAM_OID)) {
                subjectPublicKeyAlgo = PublicKeyAlgorithm.EC256;
            } else if (oid.equals(EC384_KEY_PARAM_OID)) {
                subjectPublicKeyAlgo = PublicKeyAlgorithm.EC384;
            }
            subjectPublicKeyInfoPtr = der.nextSiblingOf(subjectPublicKeyInfoPtr);
            pubKey = der.bitstringAt(subjectPublicKeyInfoPtr);
        } else if (oid.equals(RSA_KEY_OID)) {
            subjectPublicKeyAlgo = PublicKeyAlgorithm.RSA;
            subjectPublicKeyInfoPtr = der.nextSiblingOf(subjectPublicKeyInfoPtr);
            bytes memory pubKeySequence = der.bitstringAt(subjectPublicKeyInfoPtr);
            subjectPublicKeyInfoPtr = pubKeySequence.root();
            subjectPublicKeyInfoPtr = pubKeySequence.firstChildOf(subjectPublicKeyInfoPtr);
            bytes memory m = pubKeySequence.bytesAt(subjectPublicKeyInfoPtr);
            subjectPublicKeyInfoPtr = pubKeySequence.nextSiblingOf(subjectPublicKeyInfoPtr);
            bytes memory e = pubKeySequence.bytesAt(subjectPublicKeyInfoPtr);
            pubKey = abi.encode(e, m);
        }
    }

    function _parseSerialNumber(bytes memory serialBytes) private pure returns (uint256 serial) {
        uint256 shift = 8 * (32 - serialBytes.length);
        serial = uint256(bytes32(serialBytes) >> shift);
    }

    /// @dev ECDSA signature is returned as an abi-encoded tuple of (r, s)
    /// @dev SHA256 RSA PKCSv1.5 signature is returned as a bitstring as it is
    /// @dev For other signature types, the entire DER-encoded ASN1 Sequence is returned
    function _getSignatureInfo(bytes memory der, uint256 sigPtr)
        private
        pure
        returns (SignatureAlgorithm issuerSigAlgo, bytes memory sig)
    {
        // Step 1: Get Signature algo
        uint256 sigAlgoPtr = der.firstChildOf(sigPtr);
        bytes memory oid = der.bytesAt(sigAlgoPtr);

        if (oid.equals(SHA256_ECDSA_OID)) {
            issuerSigAlgo = SignatureAlgorithm.SHA256WithECDSA;
        } else if (oid.equals(SHA384_ECDSA_OID)) {
            issuerSigAlgo = SignatureAlgorithm.SHA384WithECDSA;
        } else if (oid.equals(SHA256_RSA_OID)) {
            issuerSigAlgo = SignatureAlgorithm.SHA256WithRSA;
        }

        // Step 2: Extract the signature
        // at this point, the pointer should be pointing to the bitstring
        // the first byte is a 0x03 tag, indicating that the following content is of bitstring type
        // the sceond byte is just the length of the bitstring
        // the third byte is 0x00, represents End-of-Content (EOC)
        // this is valid, because the signature of a X509 certificate is conventionally placed
        // as the last element of the entire certificate
        sigPtr = der.nextSiblingOf(sigPtr);

        if (issuerSigAlgo == SignatureAlgorithm.SHA256WithRSA) {
            sig = der.bitstringAt(sigPtr);
        } else {
            sigPtr = der.rootOfBitStringAt(sigPtr);
            sigPtr = der.firstChildOf(sigPtr);
            bytes memory r = der.bytesAt(sigPtr);
            sigPtr = der.nextSiblingOf(sigPtr);
            bytes memory s = der.bytesAt(sigPtr);

            sig = abi.encode(r, s);
        }
    }
}
