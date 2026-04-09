package registry

import (
	"testing"
)

func TestByKey_ValidKeys(t *testing.T) {
	tests := []struct {
		key     string
		chainID uint64
	}{
		{"eth_sepolia", 11155111},
		{"eth_hoodi", 560048},
		{"automata_testnet", 1398243},
	}
	for _, tt := range tests {
		n, err := ByKey(tt.key)
		if err != nil {
			t.Fatalf("ByKey(%q) error: %v", tt.key, err)
		}
		if n.ChainID != tt.chainID {
			t.Errorf("ByKey(%q).ChainID = %d, want %d", tt.key, n.ChainID, tt.chainID)
		}
	}
}

func TestByKey_InvalidKey(t *testing.T) {
	_, err := ByKey("nonexistent")
	if err == nil {
		t.Fatal("ByKey(nonexistent) should return error")
	}
}

func TestByKey_Normalized(t *testing.T) {
	tests := []string{"ETH_SEPOLIA", "eth-sepolia", "Eth Sepolia"}
	for _, key := range tests {
		n, err := ByKey(key)
		if err != nil {
			t.Fatalf("ByKey(%q) error: %v", key, err)
		}
		if n.Key != "eth_sepolia" {
			t.Errorf("ByKey(%q).Key = %q, want %q", key, n.Key, "eth_sepolia")
		}
	}
}

func TestByChainID_Valid(t *testing.T) {
	n, err := ByChainID(11155111)
	if err != nil {
		t.Fatalf("ByChainID(11155111) error: %v", err)
	}
	if n.Key != "eth_sepolia" {
		t.Errorf("got key %q, want eth_sepolia", n.Key)
	}
}

func TestByChainID_Invalid(t *testing.T) {
	_, err := ByChainID(99999)
	if err == nil {
		t.Fatal("ByChainID(99999) should return error")
	}
}

func TestDefault(t *testing.T) {
	n, err := Default()
	if err != nil {
		t.Fatalf("Default() error: %v", err)
	}
	if n.Key != "automata_testnet" {
		t.Errorf("Default().Key = %q, want automata_testnet", n.Key)
	}
}

func TestAll(t *testing.T) {
	all, err := All()
	if err != nil {
		t.Fatalf("All() error: %v", err)
	}
	if len(all) == 0 {
		t.Fatal("All() returned empty")
	}
}

func TestTestnets(t *testing.T) {
	nets, err := Testnets()
	if err != nil {
		t.Fatalf("Testnets() error: %v", err)
	}
	for _, n := range nets {
		if !n.Testnet {
			t.Errorf("Testnets() returned non-testnet: %s", n.Key)
		}
	}
}

func TestKeys(t *testing.T) {
	keys, err := Keys()
	if err != nil {
		t.Fatalf("Keys() error: %v", err)
	}
	if len(keys) == 0 {
		t.Fatal("Keys() returned empty")
	}
}

func TestChainIDs(t *testing.T) {
	ids, err := ChainIDs()
	if err != nil {
		t.Fatalf("ChainIDs() error: %v", err)
	}
	if len(ids) == 0 {
		t.Fatal("ChainIDs() returned empty")
	}
}

func TestMustByKey_Panics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("MustByKey(invalid) should panic")
		}
	}()
	MustByKey("nonexistent")
}

func TestMustByChainID_Panics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("MustByChainID(invalid) should panic")
		}
	}()
	MustByChainID(99999)
}

func TestNetwork_DefaultRpcUrl(t *testing.T) {
	n, _ := ByKey("eth_sepolia")
	url := n.DefaultRpcUrl()
	if url == "" {
		t.Fatal("DefaultRpcUrl() returned empty")
	}
}

func TestNetwork_DefaultRpcUrl_Empty(t *testing.T) {
	n := &Network{RpcEndpoints: nil}
	if n.DefaultRpcUrl() != "" {
		t.Fatal("DefaultRpcUrl() should return empty for nil endpoints")
	}
}

func TestNetwork_DefaultExplorer_Empty(t *testing.T) {
	n := &Network{BlockExplorers: nil}
	if n.DefaultExplorer() != "" {
		t.Fatal("DefaultExplorer() should return empty for nil explorers")
	}
}

func TestNormalizeNetworkKey(t *testing.T) {
	tests := []struct {
		input, want string
	}{
		{"ETH_SEPOLIA", "eth_sepolia"},
		{"eth-sepolia", "eth_sepolia"},
		{"Eth Sepolia", "eth_sepolia"},
		{"automata_testnet", "automata_testnet"},
	}
	for _, tt := range tests {
		got := normalizeNetworkKey(tt.input)
		if got != tt.want {
			t.Errorf("normalizeNetworkKey(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestWarnings_ReturnsSlice(t *testing.T) {
	// Warnings() should return a non-nil slice (may be empty if all networks loaded fine)
	w := Warnings()
	if w == nil {
		t.Fatal("Warnings() should return non-nil slice")
	}
}
