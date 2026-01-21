package registry

import (
	"encoding/json"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/common"
)

// NetworkMetadata represents the metadata for a network
type NetworkMetadata struct {
	Name            string   `json:"name"`
	ChainID         uint64   `json:"chain_id"`
	Testnet         bool     `json:"testnet"`
	RpcEndpoints    []string `json:"rpc_endpoints"`
	GasPriceHintWei *uint64  `json:"gas_price_hint_wei,omitempty"`
	BlockExplorers  []string `json:"block_explorers,omitempty"`
}

// SevDeployment represents the SEV deployment JSON structure
type SevDeployment struct {
	Verifier string `json:"VERIFIER"`
	Remark   string `json:"remark,omitempty"`
}

// parseSevDeployment parses the SEV deployment JSON and extracts contract addresses
func parseSevDeployment(data []byte) (*SevContracts, error) {
	var deployment SevDeployment
	if err := json.Unmarshal(data, &deployment); err != nil {
		return nil, fmt.Errorf("failed to parse SEV deployment: %w", err)
	}

	if deployment.Verifier == "" {
		return nil, fmt.Errorf("VERIFIER address not found in deployment")
	}

	return &SevContracts{
		Verifier: common.HexToAddress(deployment.Verifier),
	}, nil
}

// parseNetwork creates a Network from metadata and deployment data
func parseNetwork(key string, metadata *NetworkMetadata, sevData []byte) (*Network, error) {
	sev, err := parseSevDeployment(sevData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse SEV for %s: %w", key, err)
	}

	var gasPriceHint *big.Int
	if metadata.GasPriceHintWei != nil {
		gasPriceHint = new(big.Int).SetUint64(*metadata.GasPriceHintWei)
	}

	return &Network{
		Key:             key,
		DisplayName:     metadata.Name,
		ChainID:         metadata.ChainID,
		Testnet:         metadata.Testnet,
		RpcEndpoints:    metadata.RpcEndpoints,
		BlockExplorers:  metadata.BlockExplorers,
		GasPriceHintWei: gasPriceHint,
		Contracts:       *sev,
	}, nil
}

// MetadataConfig represents the full metadata JSON structure
type MetadataConfig map[string]json.RawMessage

// parseMetadata parses the metadata JSON
func parseMetadata(data []byte) (map[string]*NetworkMetadata, string, error) {
	var config MetadataConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, "", fmt.Errorf("failed to parse metadata: %w", err)
	}

	networks := make(map[string]*NetworkMetadata)
	var defaultNetwork string

	for key, raw := range config {
		if key == "default" {
			var defaultConfig struct {
				NetworkKey string `json:"network_key"`
			}
			if err := json.Unmarshal(raw, &defaultConfig); err == nil {
				defaultNetwork = defaultConfig.NetworkKey
			}
			continue
		}

		var meta NetworkMetadata
		if err := json.Unmarshal(raw, &meta); err != nil {
			continue // Skip invalid entries
		}
		networks[key] = &meta
	}

	return networks, defaultNetwork, nil
}

// normalizeNetworkKey converts various network key formats to the canonical form
func normalizeNetworkKey(key string) string {
	key = strings.ToLower(key)
	key = strings.ReplaceAll(key, "-", "_")
	key = strings.ReplaceAll(key, " ", "_")
	return key
}
