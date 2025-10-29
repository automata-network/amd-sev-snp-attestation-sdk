//SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.0;

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

struct VerifierInput {
    uint64 timestamp;
    uint8 trustedCertsPrefixLen;
    bytes rawReport;
    bytes[] vekDerChain;
}

struct VerifierJournal {
    VerificationResult result;
    uint64 timestamp;
    uint8 processorModel;
    bytes rawReport;
    bytes32[] certs;
    uint160[] certSerials;
    uint8 trustedCertsPrefixLen;
}

enum ZkCoProcessorType {
    None,
    RiscZero,
    Succinct,
    Pico
}

/**
 * @dev Enumeration of possible attestation verification results
 * Indicates the outcome of the verification process
 */
enum VerificationResult {
    // Attestation successfully verified
    Success,
    // Root certificate is not in the trusted set
    RootCertNotTrusted,
    // One or more intermediate certificates are not trusted
    IntermediateCertsNotTrusted,
    // Attestation timestamp is outside acceptable range
    InvalidTimestamp
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

interface ISnpAttestation {
    // 51abd95c
    error Unknown_Zk_Coprocessor();

    /**
     * @param zkCoProcessorType 1 - RiscZero, 2 - Succinct, 3 - Pico... etc.
     * @return this is either the IMAGE_ID for RiscZero Guest Program or
     * Succiinct Program Verifying Key
     */
    function programIdentifier(ZkCoProcessorType zkCoProcessorType) external view returns (bytes32);

    /**
     * @notice get the contract verifier for the provided ZK Co-processor
     */
    function zkVerifier(ZkCoProcessorType zkCoProcessorType) external view returns (address);

    /**
     * @dev Returns the maximum allowed time difference for attestation timestamp validation
     * @return Maximum time difference in seconds between attestation time and current block time
     */
    function maxTimeDiff() external view returns (uint64);

    function rootCerts(ProcessorType processorModel) external view returns (bytes32);
    function revokeCertCache(bytes32 _certHash) external;
    function setRootCert(ProcessorType _processorModel, bytes32 _rootCert) external;
    function setZkConfiguration(ZkCoProcessorType zkCoProcessor, ZkCoProcessorConfig memory config) external;
    function checkTrustedIntermediateCerts(ProcessorType[] calldata processorModels, bytes32[][] calldata _reportCerts)
        external
        view
        returns (uint8[] memory);

    function verifyAndAttestWithZKProof(
        bytes calldata output,
        ZkCoProcessorType zkCoprocessor,
        bytes calldata proofBytes
    ) external returns (VerifierJournal memory parsed);
}
