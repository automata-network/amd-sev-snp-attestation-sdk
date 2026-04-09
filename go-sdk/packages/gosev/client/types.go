package client

// ProcessorType represents an AMD EPYC processor generation.
// Matches the Solidity enum ProcessorType in SevSnpTypes.sol.
type ProcessorType uint8

const (
	ProcessorMilan   ProcessorType = iota // 7003 series AMD EPYC
	ProcessorGenoa                        // 9004 series AMD EPYC
	ProcessorBergamo                      // 97x4 series AMD EPYC
	ProcessorSiena                        // 8004 series AMD EPYC
)

// ZkCoProcessorType represents a ZK co-processor type.
// Matches the Solidity enum ZkCoProcessorType in SevSnpTypes.sol.
type ZkCoProcessorType uint8

const (
	ZkNone     ZkCoProcessorType = iota // Not used
	ZkRiscZero                          // RISC Zero
	ZkSuccinct                          // SP1
	ZkPico                              // Pico
)

// VerificationResult represents the outcome of on-chain attestation verification.
// Matches the Solidity enum VerificationResult in SevSnpTypes.sol.
type VerificationResult uint8

const (
	VerificationSuccess                    VerificationResult = iota // Attestation successfully verified
	VerificationRootCertNotTrusted                                  // Root certificate not trusted
	VerificationIntermediateCertsNotTrusted                         // Intermediate certificate not trusted
	VerificationInvalidTimestamp                                    // Timestamp outside acceptable range
)
