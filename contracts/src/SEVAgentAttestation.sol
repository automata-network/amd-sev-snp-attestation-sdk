//SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.0;

// ZK-Coprocessor imports:
import {IRiscZeroVerifier} from "risc0/IRiscZeroVerifier.sol";
import {ISP1Verifier} from "@sp1-contracts/ISP1Verifier.sol";
import {IPicoVerifier} from "./pico/IPicoVerifier.sol";

import {
    ProcessorType,
    ISnpAttestation,
    VerifierJournal,
    ZkCoProcessorType,
    ZkCoProcessorConfig,
    VerificationResult
} from "./interfaces/ISnpAttestation.sol";

import {Ownable} from "solady/auth/Ownable.sol";
import {EnumerableSet} from "openzeppelin/contracts/utils/structs/EnumerableSet.sol";

contract SEVAgentAttestation is Ownable, ISnpAttestation {
    using EnumerableSet for EnumerableSet.Bytes32Set;

    // use this constant to indicate that the ZK Route has been frozen
    address constant FROZEN = address(0xdead);

    mapping(ZkCoProcessorType => ZkCoProcessorConfig) _zkConfig;
    mapping(ZkCoProcessorType => EnumerableSet.Bytes32Set) _programIdConfig;
    mapping(ZkCoProcessorType => mapping(bytes4 selector => address zkVerifier)) _zkVerifierConfig;

    /// @dev Mapping of processor models to their trusted ARK certificate hashes
    mapping(ProcessorType => bytes32) internal _rootCerts;

    /// @dev Maximum allowed time difference in seconds for attestation timestamp validation
    uint64 public maxTimeDiff;

    event ZkCoProcessorUpdated(ZkCoProcessorType indexed zkCoProcessor, bytes32 programIdentifier, address zkVerifier);
    event ZkProgramIdentifierRemoved(ZkCoProcessorType indexed zkCoProcessor, bytes32 programIdentifier);
    event ZkRouteAdded(ZkCoProcessorType indexed zkCoProcessor, bytes4 selector, address zkVerifier);
    event ZkRouteFrozen(ZkCoProcessorType indexed zkCoProcessor, bytes4 selector);

    constructor(address owner, uint64 _maxTimeDiff) {
        _initializeOwner(owner);
        maxTimeDiff = _maxTimeDiff;
    }

    modifier noneZkConfigCheck(ZkCoProcessorType zkCoProcessor) {
        require(zkCoProcessor != ZkCoProcessorType.None, "Cannot use None ZK Co-Processor");
        _;
    }

    /**
     * @dev Returns the root certificate hash for a specific processor model
     * @param processorModel The processor model (ProcessorType enum)
     */
    function rootCerts(ProcessorType processorModel) external view override returns (bytes32) {
        return _rootCerts[processorModel];
    }

    /**
     * @dev Sets the maximum allowed time difference for attestation timestamp validation
     * @param _maxTimeDiff The maximum time difference in seconds
     */
    function setMaxTimeDiff(uint64 _maxTimeDiff) external onlyOwner {
        maxTimeDiff = _maxTimeDiff;
    }

    /**
     * @dev Sets the trusted root certificate hash
     * @param _processorModel Specify the Processor Model for the Root Certificate (ARK)
     * @param _rootCert Hash of the root certificate (ARK)
     *
     * Requirements:
     * - Only callable by contract owner
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
        noneZkConfigCheck(zkCoProcessor)
    {
        _zkConfig[zkCoProcessor] = config;
        _programIdConfig[zkCoProcessor].add(config.latestProgramIdentifier);
        emit ZkCoProcessorUpdated(zkCoProcessor, config.latestProgramIdentifier, config.defaultZkVerifier);
    }

    /**
     * @notice Updates the Program Identifier for the specified ZK Co-Processor
     */
    function updateProgramIdentifier(ZkCoProcessorType zkCoProcessor, bytes32 identifier)
        external
        override
        onlyOwner
        noneZkConfigCheck(zkCoProcessor)
    {
        require(identifier != bytes32(0), "Program identifier cannot be zero");
        ZkCoProcessorConfig storage config = _zkConfig[zkCoProcessor];
        require(config.latestProgramIdentifier != identifier, "Program identifier is already the latest");
        config.latestProgramIdentifier = identifier;
        _programIdConfig[zkCoProcessor].add(identifier);
        emit ZkCoProcessorUpdated(zkCoProcessor, identifier, config.defaultZkVerifier);
    }

    /**
     * @notice Deprecates a Program Identifier for the specified ZK Co-Processor
     */
    function removeProgramIdentifier(ZkCoProcessorType zkCoProcessor, bytes32 identifier)
        external
        override
        onlyOwner
        noneZkConfigCheck(zkCoProcessor)
    {
        require(_programIdConfig[zkCoProcessor].contains(identifier), "Program identifier does not exist");
        // To remove the latest program identifier
        // you must first update it with a newer program identifier
        if (_zkConfig[zkCoProcessor].latestProgramIdentifier == identifier) {
            revert ISnpAttestation.Cannot_Remove_ProgramIdentifier(zkCoProcessor, identifier);
        }
        _programIdConfig[zkCoProcessor].remove(identifier);
        emit ZkProgramIdentifierRemoved(zkCoProcessor, identifier);
    }

    /**
     * @param zkCoProcessorType 1 - RiscZero, 2 - Succinct... etc.
     * @return this is either the IMAGE_ID for RiscZero Guest Program or
     * Succiinct Program Verifying Key
     */
    function programIdentifier(ZkCoProcessorType zkCoProcessorType) external view override returns (bytes32) {
        return _zkConfig[zkCoProcessorType].latestProgramIdentifier;
    }

    /**
     * @param zkCoProcessorType 1 - RiscZero, 2 - Succinct, 3 - Pico... etc.
     * @return this returns the list of all program identifiers for the specified ZK Co-processor
     */
    function programIdentifiers(ZkCoProcessorType zkCoProcessorType) external view override returns (bytes32[] memory) {
        return _programIdConfig[zkCoProcessorType].values();
    }

    /**
     * @notice get the default contract verifier for the provided ZK Co-processor
     */
    function zkVerifier(ZkCoProcessorType zkCoProcessorType) public view override returns (address) {
        return _zkConfig[zkCoProcessorType].defaultZkVerifier;
    }

    /**
     * @notice gets the specific ZK Verifier for the provided ZK Co-processor and proof selector
     * @notice this function will revert if the provided selector has been frozen
     * @notice otherwise, if a specific ZK verifier is not configured for the provided selector
     * @notice it will return the default ZK verifier
     */
    function zkVerifier(ZkCoProcessorType zkCoProcessorType, bytes4 selector) public view override returns (address) {
        address verifier = _zkVerifierConfig[zkCoProcessorType][selector];
        if (verifier == FROZEN) {
            revert ISnpAttestation.ZK_Route_Frozen(zkCoProcessorType, selector);
        } else if (verifier == address(0)) {
            return zkVerifier(zkCoProcessorType);
        } else {
            return verifier;
        }
    }

    /**
     * @notice Adds a verifier for a specific ZK Route to override the default ZK Verifier
     */
    function addVerifyRoute(ZkCoProcessorType zkCoProcessor, bytes4 selector, address verifier)
        external
        override
        onlyOwner
        noneZkConfigCheck(zkCoProcessor)
    {
        require(verifier != address(0), "ZK Verifier cannot be zero address");
        if (_zkVerifierConfig[zkCoProcessor][selector] == FROZEN) {
            revert ISnpAttestation.ZK_Route_Frozen(zkCoProcessor, selector);
        }
        _zkVerifierConfig[zkCoProcessor][selector] = verifier;
        emit ZkRouteAdded(zkCoProcessor, selector, verifier);
    }

    /**
     * @notice PERMANENTLY freezes a ZK Route
     */
    function freezeVerifyRoute(ZkCoProcessorType zkCoProcessor, bytes4 selector)
        external
        override
        onlyOwner
        noneZkConfigCheck(zkCoProcessor)
    {
        address verifier = _zkVerifierConfig[zkCoProcessor][selector];
        if (verifier == FROZEN) {
            revert ISnpAttestation.ZK_Route_Frozen(zkCoProcessor, selector);
        }
        _zkVerifierConfig[zkCoProcessor][selector] = FROZEN;
        emit ZkRouteFrozen(zkCoProcessor, selector);
    }

    /**
     * @notice Verifies attestation using ZK proof with the latest program identifier
     */
    function verifyAndAttestWithZKProof(
        bytes calldata output,
        ZkCoProcessorType zkCoprocessor,
        bytes calldata proofBytes
    ) external override returns (VerifierJournal memory parsed) {
        bytes32 identifier = _zkConfig[zkCoprocessor].latestProgramIdentifier;
        return _verifyAndAttestWithZKProof(output, zkCoprocessor, identifier, proofBytes);
    }

    /**
     * @notice Verifies attestation using ZK proof with a specified program identifier
     */
    function verifyAndAttestWithZKProof(
        bytes calldata output,
        ZkCoProcessorType zkCoprocessor,
        bytes32 identifier,
        bytes calldata proofBytes
    ) external override returns (VerifierJournal memory parsed) {
        return _verifyAndAttestWithZKProof(output, zkCoprocessor, identifier, proofBytes);
    }

    /**
     * @notice Internal verification logic for ZK proofs
     */
    function _verifyAndAttestWithZKProof(
        bytes calldata output,
        ZkCoProcessorType zkCoprocessor,
        bytes32 identifier,
        bytes calldata proofBytes
    ) internal returns (VerifierJournal memory parsed) {
        // Validate the program identifier is in the allowed set
        if (!_programIdConfig[zkCoprocessor].contains(identifier)) {
            revert ISnpAttestation.Invalid_Program_Identifier(zkCoprocessor, identifier);
        }

        // Determine the verifier to use (route-specific or default)
        bytes4 selector = bytes4(proofBytes[0:4]);
        address verifierAddr = _zkVerifierConfig[zkCoprocessor][selector];

        if (verifierAddr == FROZEN) {
            revert ISnpAttestation.ZK_Route_Frozen(zkCoprocessor, selector);
        }

        if (verifierAddr == address(0)) {
            verifierAddr = _zkConfig[zkCoprocessor].defaultZkVerifier;
        }

        require(verifierAddr != address(0), "ZK Verifier is not configured");

        parsed = _parseJournal(output);

        if (zkCoprocessor == ZkCoProcessorType.RiscZero) {
            IRiscZeroVerifier(verifierAddr).verify(proofBytes, identifier, sha256(output));
        } else if (zkCoprocessor == ZkCoProcessorType.Succinct) {
            ISP1Verifier(verifierAddr).verifyProof(identifier, output, proofBytes);
        } else if (zkCoprocessor == ZkCoProcessorType.Pico) {
            IPicoVerifier(verifierAddr).verifyPicoProof(identifier, output, abi.decode(proofBytes, (uint256[8])));
        } else {
            revert ISnpAttestation.Unknown_Zk_Coprocessor();
        }

        parsed = _verifyJournal(parsed);

        emit AttestationSubmitted(parsed.result, zkCoprocessor, output);
    }

    /**
     * @dev Parses a raw bytes journal into a VerifierJournal struct
     * @param data Raw calldata bytes in the format:
     *   - u8 verificationResult (1 byte)
     *   - u64 timestamp (8 bytes, big-endian)
     *   - u8 processorModel (1 byte)
     *   - u32 certSize (4 bytes, big-endian)
     *   - bytes32[certSize] certs (32 * certSize bytes)
     *   - uint160[certSize] certSerials (20 * certSize bytes)
     *   - bytes32 reportHash (32 bytes)
     */
    function _parseJournal(bytes calldata data) internal pure returns (VerifierJournal memory journal) {
        uint256 offset = 0;

        journal.result = VerificationResult(uint8(data[offset]));
        offset += 1;

        journal.timestamp = uint64(bytes8(data[offset:offset + 8]));
        offset += 8;

        journal.processorModel = uint8(data[offset]);
        offset += 1;

        uint32 certSize = uint32(bytes4(data[offset:offset + 4]));
        offset += 4;

        journal.certs = new bytes32[](certSize);
        for (uint256 i = 0; i < certSize; i++) {
            journal.certs[i] = bytes32(data[offset:offset + 32]);
            offset += 32;
        }

        journal.certSerials = new uint160[](certSize);
        for (uint256 i = 0; i < certSize; i++) {
            journal.certSerials[i] = uint160(bytes20(data[offset:offset + 20]));
            offset += 20;
        }

        journal.reportHash = bytes32(data[offset:offset + 32]);
    }

    /**
     * @dev Internal function to verify and validate a journal entry
     * @param journal Verification journal to validate
     * @return Updated journal with final verification result
     *
     * Validation flow:
     * 1. Checks if the initial ZK verification was successful
     * 2. Validates the root certificate matches the trusted root for the processor model
     * 3. Validates the attestation timestamp is within acceptable range
     */
    function _verifyJournal(VerifierJournal memory journal) internal view returns (VerifierJournal memory) {
        if (journal.result != VerificationResult.Success) {
            return journal;
        }
        if (journal.certs.length == 0) {
            journal.result = VerificationResult.RootCertNotTrusted;
            return journal;
        }
        bytes32 rootCert = _rootCerts[ProcessorType(journal.processorModel)];
        if (journal.certs[0] != rootCert) {
            journal.result = VerificationResult.RootCertNotTrusted;
            return journal;
        }
        uint64 timestamp = journal.timestamp;
        if (timestamp + maxTimeDiff < block.timestamp || timestamp > block.timestamp) {
            journal.result = VerificationResult.InvalidTimestamp;
            return journal;
        }
        return journal;
    }

    function _setRootCert(ProcessorType _processorModel, bytes32 _rootCert) internal {
        _rootCerts[_processorModel] = _rootCert;
    }
}
