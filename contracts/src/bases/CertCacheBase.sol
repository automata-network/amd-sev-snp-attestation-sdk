//SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.0;

import {ProcessorType} from "../interfaces/ISnpAttestation.sol";

abstract contract CertCacheBase {
    /// @dev Mapping of trusted intermediate certificate hashes (excludes root certificate)
    mapping(bytes32 trustedCertHash => bool) public trustedIntermediateCerts;

    /// @dev Mapping of processor models to their trusted ARK certificate hashes
    mapping(ProcessorType => bytes32) internal _rootCerts;

    function _initializeTrustedCerts(bytes32[] memory initializeTrustedCerts) internal {
        for (uint256 i = 0; i < initializeTrustedCerts.length; i++) {
            trustedIntermediateCerts[initializeTrustedCerts[i]] = true;
        }
    }

    /**
     * @dev Sets the trusted root certificate hash for a specific processor model
     * @param _processorModel The processor model (ProcessorType enum cast to uint8)
     * @param _rootCert Hash of the ARK certificate for this processor model
     *
     * Requirements:
     * - Only callable by contract owner
     *
     * The root certificate serves as the trust anchor for all certificate chain validations.
     * Different AMD SEV-SNP processors use certificates issued from different root certificates.
     */
    function _setRootCert(ProcessorType _processorModel, bytes32 _rootCert) internal {
        _rootCerts[_processorModel] = _rootCert;
    }

    /**
     * @dev Revokes a trusted intermediate certificate
     * @param _certHash Hash of the certificate to revoke
     *
     * Requirements:
     * - Only callable by contract owner
     * - Certificate must exist in the trusted intermediate certificates set
     *
     * This function allows the owner to revoke compromised intermediate certificates
     * without affecting the root certificate or other trusted certificates.
     */
    function _revokeCertCache(bytes32 _certHash) internal {
        if (!trustedIntermediateCerts[_certHash]) {
            revert("Certificate not found in trusted certs");
        }
        delete trustedIntermediateCerts[_certHash];
    }

    /**
     * @dev Internal function to cache newly discovered trusted certificates
     * @param certs Certificate hashes for entire cert chain (root -> leaf)
     * @param trustedCertsPrefixLen Length of the prefix of trusted certificates in the chain
     *
     * This function automatically adds any certificates beyond the trusted length
     * to the trusted intermediate certificates set. This optimizes future verifications
     * by expanding the known trusted certificate set based on successful verifications.
     */
    function _cacheNewCert(bytes32[] memory certs, uint256 trustedCertsPrefixLen) internal {
        for (uint256 i = trustedCertsPrefixLen; i < certs.length; i++) {
            bytes32 certHash = certs[i];
            trustedIntermediateCerts[certHash] = true;
        }
    }

    /**
     * @dev Checks the prefix length of trusted certificates in each provided certificate chain for reports
     * @param _processorModels Array of processor models corresponding to each certificate chain
     * @param _reportCerts Array of certificate chains, each containing certificate hashes
     * @return Array indicating the prefix length of trusted certificates in each chain
     *
     * For each certificate chain:
     * 1. Validates that the first certificate matches the stored root certificate for the processor model
     * 2. Counts consecutive trusted certificates starting from the root
     * 3. Stops counting when an untrusted certificate is encountered
     *
     * This function is used to pre-validate certificate chains before generating proofs,
     * helping to optimize the proving process by determining trusted certificate lengths.
     * Usually called from off-chain
     */
    function _checkTrustedIntermediateCerts(
        ProcessorType[] calldata _processorModels,
        bytes32[][] calldata _reportCerts
    ) internal view returns (uint8[] memory) {
        require(_reportCerts.length == _processorModels.length, "Array length mismatch");
        uint8[] memory results = new uint8[](_reportCerts.length);

        for (uint256 i = 0; i < _reportCerts.length; i++) {
            bytes32[] calldata certs = _reportCerts[i];
            bytes32 expectedRootCert = _rootCerts[_processorModels[i]];

            if (expectedRootCert == bytes32(0)) {
                revert("Root certificate not set for this processor model");
            }

            uint8 trustedCertPrefixLen = 1;
            if (certs[0] != expectedRootCert) {
                revert("First certificate must be the root certificate for the specified processor model");
            }

            for (uint256 j = 1; j < certs.length; j++) {
                if (!trustedIntermediateCerts[certs[j]]) {
                    break;
                }
                trustedCertPrefixLen += 1;
            }
            results[i] = trustedCertPrefixLen;
        }
        return results;
    }
}
