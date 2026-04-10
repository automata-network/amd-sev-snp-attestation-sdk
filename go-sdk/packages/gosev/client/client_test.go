package client

import (
	"testing"

	"github.com/automata-network/amd-sev-snp-attestation-sdk/go-sdk/packages/gosev/registry"
)

func TestNewClient_NoRpcEndpoints(t *testing.T) {
	network := &registry.Network{
		Key:          "test",
		RpcEndpoints: nil,
	}
	_, err := NewClient(network)
	if err == nil {
		t.Fatal("NewClient should fail with no RPC endpoints")
	}
}

func TestNewClient_EmptyRpcEndpoints(t *testing.T) {
	network := &registry.Network{
		Key:          "test",
		RpcEndpoints: []string{},
	}
	_, err := NewClient(network)
	if err == nil {
		t.Fatal("NewClient should fail with empty RPC endpoints")
	}
}

func TestNewClientWithRPC_InvalidURL(t *testing.T) {
	network := &registry.Network{
		Key:          "test",
		RpcEndpoints: []string{"http://localhost:1"},
	}
	// This may or may not fail at Dial time depending on the go-ethereum version.
	// The important thing is it doesn't panic.
	_, _ = NewClientWithRPC(network, "not-a-valid-url://bad")
}

func TestCheckTrustedCerts_TypeConversion(t *testing.T) {
	// Test that ProcessorType -> uint8 conversion works correctly
	models := []ProcessorType{ProcessorMilan, ProcessorGenoa, ProcessorBergamo, ProcessorSiena}
	expected := []uint8{0, 1, 2, 3}
	for i, m := range models {
		if uint8(m) != expected[i] {
			t.Errorf("ProcessorType(%d) = %d, want %d", i, uint8(m), expected[i])
		}
	}
}

func TestZkCoProcessorType_Values(t *testing.T) {
	if uint8(ZkNone) != 0 {
		t.Errorf("ZkNone = %d, want 0", ZkNone)
	}
	if uint8(ZkRiscZero) != 1 {
		t.Errorf("ZkRiscZero = %d, want 1", ZkRiscZero)
	}
	if uint8(ZkSuccinct) != 2 {
		t.Errorf("ZkSuccinct = %d, want 2", ZkSuccinct)
	}
	if uint8(ZkPico) != 3 {
		t.Errorf("ZkPico = %d, want 3", ZkPico)
	}
}

func TestVerificationResult_Values(t *testing.T) {
	if uint8(VerificationSuccess) != 0 {
		t.Errorf("VerificationSuccess = %d, want 0", VerificationSuccess)
	}
	if uint8(VerificationRootCertNotTrusted) != 1 {
		t.Errorf("VerificationRootCertNotTrusted = %d, want 1", VerificationRootCertNotTrusted)
	}
	if uint8(VerificationIntermediateCertsNotTrusted) != 2 {
		t.Errorf("VerificationIntermediateCertsNotTrusted = %d, want 2", VerificationIntermediateCertsNotTrusted)
	}
	if uint8(VerificationInvalidTimestamp) != 3 {
		t.Errorf("VerificationInvalidTimestamp = %d, want 3", VerificationInvalidTimestamp)
	}
}

func TestNewClient_WithRegistryNetwork(t *testing.T) {
	// Use a real registry network — this tests that the constructor accepts
	// registry.Network pointers and dials the RPC.
	// We expect a dial error or timeout since we're not on testnet, but it should not panic.
	network := registry.MustByKey("automata_testnet")
	client, err := NewClient(network)
	if err != nil {
		// Dial failure is acceptable in test env
		t.Skipf("Skipping: cannot connect to testnet RPC: %v", err)
	}
	if client.Network().Key != "automata_testnet" {
		t.Errorf("Network().Key = %q, want automata_testnet", client.Network().Key)
	}
}
