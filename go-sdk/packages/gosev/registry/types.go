package registry

import (
	"math/big"

	"github.com/ethereum/go-ethereum/common"
)

// SevContracts holds SEV attestation contract addresses
type SevContracts struct {
	// SEVAgentAttestationVerifier contract address
	Verifier common.Address
}

// Network represents a blockchain network configuration with SEV contracts
type Network struct {
	Key             string   // Unique identifier (e.g., "eth_sepolia")
	DisplayName     string   // Human-readable name (e.g., "Ethereum Sepolia")
	ChainID         uint64   // EVM chain ID
	Testnet         bool     // Whether this is a testnet
	RpcEndpoints    []string // Ordered by preference
	BlockExplorers  []string // Block explorer URLs
	GasPriceHintWei *big.Int // Optional gas price hint
	Contracts       SevContracts
}

// DefaultRpcUrl returns the first (preferred) RPC endpoint
func (n *Network) DefaultRpcUrl() string {
	if len(n.RpcEndpoints) > 0 {
		return n.RpcEndpoints[0]
	}
	return ""
}

// DefaultExplorer returns the first block explorer URL
func (n *Network) DefaultExplorer() string {
	if len(n.BlockExplorers) > 0 {
		return n.BlockExplorers[0]
	}
	return ""
}

// VerifierAddress returns the SEVAgentAttestationVerifier contract address
func (n *Network) VerifierAddress() common.Address {
	return n.Contracts.Verifier
}
