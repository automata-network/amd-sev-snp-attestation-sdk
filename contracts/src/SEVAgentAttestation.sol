//SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.0;

// ZK-Coprocessor imports:
import {IRiscZeroVerifier} from "risc0/IRiscZeroVerifier.sol";
import {ISP1Verifier} from "@sp1-contracts/ISP1Verifier.sol";
import {
    ISnpAttestation,
    VerifierInput,
    VerifierJournal,
    ZkCoProcessorType,
    ZkCoProcessorConfig,
    VerificationResult
} from "./interfaces/ISnpAttestation.sol";

import {CertCacheBase} from "./bases/CertCacheBase.sol";
import {Ownable} from "solady/auth/Ownable.sol";

import {ProcessorType} from "./types/SevSnpTypes.sol";

contract SEVAgentAttestation is Ownable, CertCacheBase, ISnpAttestation {
    mapping(ZkCoProcessorType => ZkCoProcessorConfig) _zkConfig;

    /// @dev Maximum allowed time difference in seconds for attestation timestamp validation
    uint64 public maxTimeDiff;

    constructor(uint64 _maxTimeDiff, bytes32[] memory initializeTrustedCerts) {
        maxTimeDiff = _maxTimeDiff;
        _initializeTrustedCerts(initializeTrustedCerts);
        _initializeOwner(msg.sender);
    }

    function rootCerts(ProcessorType processorModel) external view override returns (bytes32) {
        return _rootCerts[processorModel];
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
    function revokeCertCache(bytes32 _certHash) external override onlyOwner {
        _revokeCertCache(_certHash);
    }

    /**
     * @dev Sets the trusted root certificate hash
     * @param _processorModel Specify the Processor Model for the Root Certificate (ARK)
     * @param _rootCert Hash of the AWS Nitro Enclave root certificate
     *
     * Requirements:
     * - Only callable by contract owner
     *
     * The root certificate serves as the trust anchor for all certificate chain validations.
     * This should be set to the hash of AWS's root certificate for Nitro Enclaves.
     */
    function setRootCert(ProcessorType _processorModel, bytes32 _rootCert) external override onlyOwner {
        _setRootCert(_processorModel, _rootCert);
    }

    /**
     * @notice Sets the ZK Configuration for the given ZK Co-Processor
     */
    function setZkConfiguration(ZkCoProcessorType zkCoProcessor, ZkCoProcessorConfig memory config)
        external
        override
        onlyOwner
    {
        _zkConfig[zkCoProcessor] = config;
    }

    /**
     * @param zkCoProcessorType 1 - RiscZero, 2 - Succinct... etc.
     * @return this is either the IMAGE_ID for RiscZero Guest Program or
     * Succiinct Program Verifying Key
     */
    function programIdentifier(ZkCoProcessorType zkCoProcessorType) external view override returns (bytes32) {
        return _zkConfig[zkCoProcessorType].programIdentifier;
    }

    /**
     * @notice get the contract verifier for the provided ZK Co-processor
     */
    function zkVerifier(ZkCoProcessorType zkCoProcessorType) external view override returns (address) {
        return _zkConfig[zkCoProcessorType].zkVerifier;
    }

    function checkTrustedIntermediateCerts(ProcessorType[] calldata processorModels, bytes32[][] calldata reportCerts) external view override returns (uint8[] memory) {
        return _checkTrustedIntermediateCerts(processorModels, reportCerts);
    }

    function verifyAndAttestWithZKProof(
        bytes calldata output,
        ZkCoProcessorType zkCoprocessor,
        bytes calldata proofBytes
    ) external returns (VerifierJournal memory parsed) {
        ZkCoProcessorConfig memory zkConfig = _zkConfig[zkCoprocessor];

        parsed = abi.decode(output, (VerifierJournal));

        if (zkCoprocessor == ZkCoProcessorType.RiscZero) {
            IRiscZeroVerifier(zkConfig.zkVerifier).verify(proofBytes, zkConfig.programIdentifier, sha256(output));
        } else if (zkCoprocessor == ZkCoProcessorType.Succinct) {
            ISP1Verifier(zkConfig.zkVerifier).verifyProof(zkConfig.programIdentifier, output, proofBytes);
        } else {
            revert ISnpAttestation.Unknown_Zk_Coprocessor();
        }

        parsed = _verifyJournal(parsed);
    }

    /**
     * @dev Internal function to verify and validate a journal entry
     * @param journal Verification journal to validate
     * @return Updated journal with final verification result
     *
     * This function performs comprehensive validation:
     * 1. Checks if the initial ZK verification was successful
     * 2. Validates the root certificate matches the trusted root
     * 3. Ensures all trusted certificates are still valid (not revoked)
     * 4. Validates the attestation timestamp is within acceptable range
     * 5. Caches newly discovered certificates for future use
     *
     * The timestamp validation converts milliseconds to seconds and checks:
     * - Attestation is not too old (timestamp + maxTimeDiff >= block.timestamp)
     * - Attestation is not from the future (timestamp <= block.timestamp)
     */
    function _verifyJournal(VerifierJournal memory journal) internal returns (VerifierJournal memory) {
        if (journal.result != VerificationResult.Success) {
            return journal;
        }
        if (journal.trustedCertsPrefixLen == 0) {
            journal.result = VerificationResult.RootCertNotTrusted;
            return journal;
        }
        // Check every trusted certificate to ensure none have been revoked
        for (uint256 i = 0; i < journal.trustedCertsPrefixLen; i++) {
            bytes32 certHash = journal.certs[i];
            bytes32 rootCert = _rootCerts[ProcessorType(journal.processorModel)];
            if (i == 0) {
                if (certHash != rootCert) {
                    journal.result = VerificationResult.RootCertNotTrusted;
                    return journal;
                }
                continue;
            }
            if (!trustedIntermediateCerts[certHash]) {
                journal.result = VerificationResult.IntermediateCertsNotTrusted;
                return journal;
            }
        }
        uint64 timestamp = journal.timestamp;
        if (timestamp + maxTimeDiff < block.timestamp || timestamp > block.timestamp) {
            journal.result = VerificationResult.InvalidTimestamp;
            return journal;
        }
        _cacheNewCert(journal.certs, journal.trustedCertsPrefixLen);
        return journal;
    }
}
