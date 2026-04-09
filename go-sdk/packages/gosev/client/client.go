package client

import (
	"context"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"

	"github.com/automata-network/amd-sev-snp-attestation-sdk/go-sdk/packages/gosev/bindings"
	"github.com/automata-network/amd-sev-snp-attestation-sdk/go-sdk/packages/gosev/registry"
)

// Client provides read-only access to the SEVAgentAttestation contract.
type Client struct {
	caller  *bindings.SEVAgentAttestationCaller
	network *registry.Network
}

// NewClient creates a client using the network's default RPC endpoint.
func NewClient(network *registry.Network) (*Client, error) {
	rpcURL := network.DefaultRpcUrl()
	if rpcURL == "" {
		return nil, fmt.Errorf("network %s has no RPC endpoints", network.Key)
	}
	return NewClientWithRPC(network, rpcURL)
}

// NewClientWithRPC creates a client with a custom RPC URL.
func NewClientWithRPC(network *registry.Network, rpcURL string) (*Client, error) {
	ethClient, err := ethclient.Dial(rpcURL)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to %s: %w", rpcURL, err)
	}
	caller, err := bindings.NewSEVAgentAttestationCaller(network.VerifierAddress(), ethClient)
	if err != nil {
		return nil, fmt.Errorf("failed to bind contract at %s: %w", network.VerifierAddress().Hex(), err)
	}
	return &Client{caller: caller, network: network}, nil
}

// Network returns the network this client is connected to.
func (c *Client) Network() *registry.Network {
	return c.network
}

// RootCerts returns the root certificate hash for a processor type.
func (c *Client) RootCerts(ctx context.Context, processorType ProcessorType) ([32]byte, error) {
	return c.caller.RootCerts(&bind.CallOpts{Context: ctx}, uint8(processorType))
}

// IsTrustedCert checks if a certificate hash is in the trusted set.
func (c *Client) IsTrustedCert(ctx context.Context, certHash [32]byte) (bool, error) {
	return c.caller.TrustedIntermediateCerts(&bind.CallOpts{Context: ctx}, certHash)
}

// CheckTrustedCerts batch-validates certificate chains against the trust store.
// reportCerts is a 2D array: one [][32]byte per processor model.
// Returns a trust level (uint8) per processor model.
func (c *Client) CheckTrustedCerts(ctx context.Context, processorModels []ProcessorType, reportCerts [][][32]byte) ([]uint8, error) {
	models := make([]uint8, len(processorModels))
	for i, m := range processorModels {
		models[i] = uint8(m)
	}
	return c.caller.CheckTrustedIntermediateCerts(&bind.CallOpts{Context: ctx}, models, reportCerts)
}

// ZkVerifier returns the default verifier contract address for a ZK co-processor type.
func (c *Client) ZkVerifier(ctx context.Context, zkType ZkCoProcessorType) (common.Address, error) {
	return c.caller.ZkVerifier(&bind.CallOpts{Context: ctx}, uint8(zkType))
}

// ZkVerifierWithSelector returns the route-specific verifier for a ZK co-processor type and selector.
func (c *Client) ZkVerifierWithSelector(ctx context.Context, zkType ZkCoProcessorType, selector [4]byte) (common.Address, error) {
	return c.caller.ZkVerifier0(&bind.CallOpts{Context: ctx}, uint8(zkType), selector)
}

// ProgramIdentifier returns the latest ZK program identifier.
func (c *Client) ProgramIdentifier(ctx context.Context, zkType ZkCoProcessorType) ([32]byte, error) {
	return c.caller.ProgramIdentifier(&bind.CallOpts{Context: ctx}, uint8(zkType))
}

// ProgramIdentifiers returns all valid ZK program identifiers.
func (c *Client) ProgramIdentifiers(ctx context.Context, zkType ZkCoProcessorType) ([][32]byte, error) {
	return c.caller.ProgramIdentifiers(&bind.CallOpts{Context: ctx}, uint8(zkType))
}

// MaxTimeDiff returns the maximum allowed time difference (seconds) for attestation timestamp validation.
func (c *Client) MaxTimeDiff(ctx context.Context) (uint64, error) {
	return c.caller.MaxTimeDiff(&bind.CallOpts{Context: ctx})
}

// Owner returns the contract owner address.
func (c *Client) Owner(ctx context.Context) (common.Address, error) {
	return c.caller.Owner(&bind.CallOpts{Context: ctx})
}

// OwnershipHandoverExpiresAt returns the expiration timestamp for a pending ownership handover.
func (c *Client) OwnershipHandoverExpiresAt(ctx context.Context, pendingOwner common.Address) (*big.Int, error) {
	return c.caller.OwnershipHandoverExpiresAt(&bind.CallOpts{Context: ctx}, pendingOwner)
}
