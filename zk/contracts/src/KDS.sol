//SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import {Ownable} from "solady/auth/Ownable.sol";
import "./bases/KDSBase.sol";

interface IX509RiscZeroVerifier {
    function verifyX509ChainProof(bytes[] calldata derX509Chain, bytes calldata seal) external view;
}

contract KDS is Ownable, KDSBase {
    using LibString for string;

    IX509RiscZeroVerifier public x509RiscZeroVerifier;

    mapping(ProcessorType => bytes32 rootKeyHash) _rootCaKeyHashes;

    constructor(address _x509Verifier) {
        x509RiscZeroVerifier = IX509RiscZeroVerifier(_x509Verifier);
        _initializeOwner(msg.sender);
    }

    error Invalid_Root_Key(ProcessorType processor);
    error Missing_Issuer(ProcessorType processor, CertType CertType);

    /// @dev RSA pubkey, abi.encode(exponent, modulus)
    /// @dev ECDSA pubkey. uncompressed (prefixed with 0x04), concatenated with x and y coordinates
    function configureRootPubkey(ProcessorType processorModel, bytes calldata pubkey) external onlyOwner {
        _rootCaKeyHashes[processorModel] = keccak256(pubkey);
        bytes32 key = _computeARKKey(processorModel);
        delete _certs[key];
        delete _certHashes[key];
    }

    function setX509Verifier(address _x509Verifier) external onlyOwner {
        x509RiscZeroVerifier = IX509RiscZeroVerifier(_x509Verifier);
    }

    function upsertVekCaChain(bytes[] calldata certchain, bytes calldata seal) public override {
        if (certchain.length > 2 || certchain.length == 0) {
            revert Incorrect_Vek_CA_Chain_Length();
        } else {
            bytes[] memory input;
            bytes memory leaf = certchain[0];

            (CertType caType, string[] memory caSubjectCnSplit) = _checkVekCaType(leaf);

            ProcessorType processor;

            if (caType == CertType.ARK) {
                input = new bytes[](1);
                processor = _parseArkCn(caSubjectCnSplit);
                _checkRootKey(processor, leaf);
                input[0] = leaf;
                _upsertArk(leaf, processor);
            } else {
                CertType vekType;
                (processor, vekType) = _parseAskCn(caSubjectCnSplit);
                bytes memory issuer = _certs[_computeARKKey(processor)];
                if (issuer.length == 0 && certchain[1].length == 0) {
                    revert Missing_Issuer(processor, CertType.ASK);
                } else if (issuer.length > 0) {
                    input = new bytes[](2);
                    input[0] = leaf;
                    input[1] = issuer;
                }
                _upsertAsk(leaf, processor, vekType);
            }

            if (certchain.length == 2) {
                input = new bytes[](2);
                bytes memory root = certchain[1];
                _checkRootKey(processor, root);

                _upsertArk(root, processor);

                input = new bytes[](2);
                input[0] = leaf;
                input[1] = root;
            }

            x509RiscZeroVerifier.verifyX509ChainProof(input, seal);
        }
    }

    function upsertVekCert(bytes calldata vek, bytes calldata seal) public override {
        (ProcessorType processorModel, CertType vekType, TcbVersion memory tcb,) = _parseVek(vek);

        (bytes memory ask, bytes memory ark) = fetchCa(processorModel, vekType);
        if (ask.length == 0) {
            revert Missing_Issuer(processorModel, vekType);
        }
        if (ark.length == 0) {
            revert Missing_Issuer(processorModel, CertType.ASK);
        }

        bytes[] memory certchain = new bytes[](3);
        certchain[0] = vek;
        certchain[1] = ask;
        certchain[2] = ark;

        x509RiscZeroVerifier.verifyX509ChainProof(certchain, seal);

        _upsertVek(vek, processorModel, vekType, tcb);
    }

    function _checkRootKey(ProcessorType processorModel, bytes memory root) private view {
        (, bytes memory pubkey) = X509Helper.getSubjectPublicKeyInfo(root);
        if (_rootCaKeyHashes[processorModel] != keccak256(pubkey)) {
            revert Invalid_Root_Key(processorModel);
        }
    }
}
