// Code generated - DO NOT EDIT.
// This file is a generated binding and any manual changes will be lost.

package bindings

import (
	"errors"
	"math/big"
	"strings"

	ethereum "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/event"
)

// Reference imports to suppress errors if they are not otherwise used.
var (
	_ = errors.New
	_ = big.NewInt
	_ = strings.NewReader
	_ = ethereum.NotFound
	_ = bind.Bind
	_ = common.Big1
	_ = types.BloomLookup
	_ = event.NewSubscription
	_ = abi.ConvertType
)

// VerifierJournal is an auto generated low-level Go binding around an user-defined struct.
type VerifierJournal struct {
	Result                uint8
	Timestamp             uint64
	ProcessorModel        uint8
	RawReport             []byte
	Certs                 [][32]byte
	CertSerials           []*big.Int
	TrustedCertsPrefixLen uint8
}

// ZkCoProcessorConfig is an auto generated low-level Go binding around an user-defined struct.
type ZkCoProcessorConfig struct {
	LatestProgramIdentifier [32]byte
	DefaultZkVerifier       common.Address
}

// SEVAgentAttestationMetaData contains all meta data concerning the SEVAgentAttestation contract.
var SEVAgentAttestationMetaData = &bind.MetaData{
	ABI: "[{\"type\":\"constructor\",\"inputs\":[{\"name\":\"owner\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"_maxTimeDiff\",\"type\":\"uint64\",\"internalType\":\"uint64\"},{\"name\":\"initializeTrustedCerts\",\"type\":\"bytes32[]\",\"internalType\":\"bytes32[]\"}],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"addVerifyRoute\",\"inputs\":[{\"name\":\"zkCoProcessor\",\"type\":\"uint8\",\"internalType\":\"enumZkCoProcessorType\"},{\"name\":\"selector\",\"type\":\"bytes4\",\"internalType\":\"bytes4\"},{\"name\":\"verifier\",\"type\":\"address\",\"internalType\":\"address\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"cancelOwnershipHandover\",\"inputs\":[],\"outputs\":[],\"stateMutability\":\"payable\"},{\"type\":\"function\",\"name\":\"checkTrustedIntermediateCerts\",\"inputs\":[{\"name\":\"processorModels\",\"type\":\"uint8[]\",\"internalType\":\"enumProcessorType[]\"},{\"name\":\"reportCerts\",\"type\":\"bytes32[][]\",\"internalType\":\"bytes32[][]\"}],\"outputs\":[{\"name\":\"\",\"type\":\"uint8[]\",\"internalType\":\"uint8[]\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"completeOwnershipHandover\",\"inputs\":[{\"name\":\"pendingOwner\",\"type\":\"address\",\"internalType\":\"address\"}],\"outputs\":[],\"stateMutability\":\"payable\"},{\"type\":\"function\",\"name\":\"freezeVerifyRoute\",\"inputs\":[{\"name\":\"zkCoProcessor\",\"type\":\"uint8\",\"internalType\":\"enumZkCoProcessorType\"},{\"name\":\"selector\",\"type\":\"bytes4\",\"internalType\":\"bytes4\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"maxTimeDiff\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"uint64\",\"internalType\":\"uint64\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"owner\",\"inputs\":[],\"outputs\":[{\"name\":\"result\",\"type\":\"address\",\"internalType\":\"address\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"ownershipHandoverExpiresAt\",\"inputs\":[{\"name\":\"pendingOwner\",\"type\":\"address\",\"internalType\":\"address\"}],\"outputs\":[{\"name\":\"result\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"programIdentifier\",\"inputs\":[{\"name\":\"zkCoProcessorType\",\"type\":\"uint8\",\"internalType\":\"enumZkCoProcessorType\"}],\"outputs\":[{\"name\":\"\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"programIdentifiers\",\"inputs\":[{\"name\":\"zkCoProcessorType\",\"type\":\"uint8\",\"internalType\":\"enumZkCoProcessorType\"}],\"outputs\":[{\"name\":\"\",\"type\":\"bytes32[]\",\"internalType\":\"bytes32[]\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"removeProgramIdentifier\",\"inputs\":[{\"name\":\"zkCoProcessor\",\"type\":\"uint8\",\"internalType\":\"enumZkCoProcessorType\"},{\"name\":\"identifier\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"renounceOwnership\",\"inputs\":[],\"outputs\":[],\"stateMutability\":\"payable\"},{\"type\":\"function\",\"name\":\"requestOwnershipHandover\",\"inputs\":[],\"outputs\":[],\"stateMutability\":\"payable\"},{\"type\":\"function\",\"name\":\"revokeCertCache\",\"inputs\":[{\"name\":\"_certHash\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"rootCerts\",\"inputs\":[{\"name\":\"processorModel\",\"type\":\"uint8\",\"internalType\":\"enumProcessorType\"}],\"outputs\":[{\"name\":\"\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"setMaxTimeDiff\",\"inputs\":[{\"name\":\"_maxTimeDiff\",\"type\":\"uint64\",\"internalType\":\"uint64\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"setRootCert\",\"inputs\":[{\"name\":\"_processorModel\",\"type\":\"uint8\",\"internalType\":\"enumProcessorType\"},{\"name\":\"_rootCert\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"setZkConfiguration\",\"inputs\":[{\"name\":\"zkCoProcessor\",\"type\":\"uint8\",\"internalType\":\"enumZkCoProcessorType\"},{\"name\":\"config\",\"type\":\"tuple\",\"internalType\":\"structZkCoProcessorConfig\",\"components\":[{\"name\":\"latestProgramIdentifier\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"defaultZkVerifier\",\"type\":\"address\",\"internalType\":\"address\"}]}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"transferOwnership\",\"inputs\":[{\"name\":\"newOwner\",\"type\":\"address\",\"internalType\":\"address\"}],\"outputs\":[],\"stateMutability\":\"payable\"},{\"type\":\"function\",\"name\":\"trustedIntermediateCerts\",\"inputs\":[{\"name\":\"trustedCertHash\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"}],\"outputs\":[{\"name\":\"\",\"type\":\"bool\",\"internalType\":\"bool\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"updateProgramIdentifier\",\"inputs\":[{\"name\":\"zkCoProcessor\",\"type\":\"uint8\",\"internalType\":\"enumZkCoProcessorType\"},{\"name\":\"identifier\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"verifyAndAttestWithZKProof\",\"inputs\":[{\"name\":\"output\",\"type\":\"bytes\",\"internalType\":\"bytes\"},{\"name\":\"zkCoprocessor\",\"type\":\"uint8\",\"internalType\":\"enumZkCoProcessorType\"},{\"name\":\"identifier\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"proofBytes\",\"type\":\"bytes\",\"internalType\":\"bytes\"}],\"outputs\":[{\"name\":\"parsed\",\"type\":\"tuple\",\"internalType\":\"structVerifierJournal\",\"components\":[{\"name\":\"result\",\"type\":\"uint8\",\"internalType\":\"enumVerificationResult\"},{\"name\":\"timestamp\",\"type\":\"uint64\",\"internalType\":\"uint64\"},{\"name\":\"processorModel\",\"type\":\"uint8\",\"internalType\":\"uint8\"},{\"name\":\"rawReport\",\"type\":\"bytes\",\"internalType\":\"bytes\"},{\"name\":\"certs\",\"type\":\"bytes32[]\",\"internalType\":\"bytes32[]\"},{\"name\":\"certSerials\",\"type\":\"uint160[]\",\"internalType\":\"uint160[]\"},{\"name\":\"trustedCertsPrefixLen\",\"type\":\"uint8\",\"internalType\":\"uint8\"}]}],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"verifyAndAttestWithZKProof\",\"inputs\":[{\"name\":\"output\",\"type\":\"bytes\",\"internalType\":\"bytes\"},{\"name\":\"zkCoprocessor\",\"type\":\"uint8\",\"internalType\":\"enumZkCoProcessorType\"},{\"name\":\"proofBytes\",\"type\":\"bytes\",\"internalType\":\"bytes\"}],\"outputs\":[{\"name\":\"parsed\",\"type\":\"tuple\",\"internalType\":\"structVerifierJournal\",\"components\":[{\"name\":\"result\",\"type\":\"uint8\",\"internalType\":\"enumVerificationResult\"},{\"name\":\"timestamp\",\"type\":\"uint64\",\"internalType\":\"uint64\"},{\"name\":\"processorModel\",\"type\":\"uint8\",\"internalType\":\"uint8\"},{\"name\":\"rawReport\",\"type\":\"bytes\",\"internalType\":\"bytes\"},{\"name\":\"certs\",\"type\":\"bytes32[]\",\"internalType\":\"bytes32[]\"},{\"name\":\"certSerials\",\"type\":\"uint160[]\",\"internalType\":\"uint160[]\"},{\"name\":\"trustedCertsPrefixLen\",\"type\":\"uint8\",\"internalType\":\"uint8\"}]}],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"zkVerifier\",\"inputs\":[{\"name\":\"zkCoProcessorType\",\"type\":\"uint8\",\"internalType\":\"enumZkCoProcessorType\"}],\"outputs\":[{\"name\":\"\",\"type\":\"address\",\"internalType\":\"address\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"zkVerifier\",\"inputs\":[{\"name\":\"zkCoProcessorType\",\"type\":\"uint8\",\"internalType\":\"enumZkCoProcessorType\"},{\"name\":\"selector\",\"type\":\"bytes4\",\"internalType\":\"bytes4\"}],\"outputs\":[{\"name\":\"\",\"type\":\"address\",\"internalType\":\"address\"}],\"stateMutability\":\"view\"},{\"type\":\"event\",\"name\":\"AttestationSubmitted\",\"inputs\":[{\"name\":\"result\",\"type\":\"uint8\",\"indexed\":false,\"internalType\":\"enumVerificationResult\"},{\"name\":\"zkCoProcessor\",\"type\":\"uint8\",\"indexed\":false,\"internalType\":\"enumZkCoProcessorType\"},{\"name\":\"output\",\"type\":\"bytes\",\"indexed\":false,\"internalType\":\"bytes\"}],\"anonymous\":false},{\"type\":\"event\",\"name\":\"OwnershipHandoverCanceled\",\"inputs\":[{\"name\":\"pendingOwner\",\"type\":\"address\",\"indexed\":true,\"internalType\":\"address\"}],\"anonymous\":false},{\"type\":\"event\",\"name\":\"OwnershipHandoverRequested\",\"inputs\":[{\"name\":\"pendingOwner\",\"type\":\"address\",\"indexed\":true,\"internalType\":\"address\"}],\"anonymous\":false},{\"type\":\"event\",\"name\":\"OwnershipTransferred\",\"inputs\":[{\"name\":\"oldOwner\",\"type\":\"address\",\"indexed\":true,\"internalType\":\"address\"},{\"name\":\"newOwner\",\"type\":\"address\",\"indexed\":true,\"internalType\":\"address\"}],\"anonymous\":false},{\"type\":\"event\",\"name\":\"ZkCoProcessorUpdated\",\"inputs\":[{\"name\":\"zkCoProcessor\",\"type\":\"uint8\",\"indexed\":true,\"internalType\":\"enumZkCoProcessorType\"},{\"name\":\"programIdentifier\",\"type\":\"bytes32\",\"indexed\":false,\"internalType\":\"bytes32\"},{\"name\":\"zkVerifier\",\"type\":\"address\",\"indexed\":false,\"internalType\":\"address\"}],\"anonymous\":false},{\"type\":\"event\",\"name\":\"ZkProgramIdentifierRemoved\",\"inputs\":[{\"name\":\"zkCoProcessor\",\"type\":\"uint8\",\"indexed\":true,\"internalType\":\"enumZkCoProcessorType\"},{\"name\":\"programIdentifier\",\"type\":\"bytes32\",\"indexed\":false,\"internalType\":\"bytes32\"}],\"anonymous\":false},{\"type\":\"event\",\"name\":\"ZkRouteAdded\",\"inputs\":[{\"name\":\"zkCoProcessor\",\"type\":\"uint8\",\"indexed\":true,\"internalType\":\"enumZkCoProcessorType\"},{\"name\":\"selector\",\"type\":\"bytes4\",\"indexed\":false,\"internalType\":\"bytes4\"},{\"name\":\"zkVerifier\",\"type\":\"address\",\"indexed\":false,\"internalType\":\"address\"}],\"anonymous\":false},{\"type\":\"event\",\"name\":\"ZkRouteFrozen\",\"inputs\":[{\"name\":\"zkCoProcessor\",\"type\":\"uint8\",\"indexed\":true,\"internalType\":\"enumZkCoProcessorType\"},{\"name\":\"selector\",\"type\":\"bytes4\",\"indexed\":false,\"internalType\":\"bytes4\"}],\"anonymous\":false},{\"type\":\"error\",\"name\":\"AlreadyInitialized\",\"inputs\":[]},{\"type\":\"error\",\"name\":\"Cannot_Remove_ProgramIdentifier\",\"inputs\":[{\"name\":\"zkCoProcessor\",\"type\":\"uint8\",\"internalType\":\"enumZkCoProcessorType\"},{\"name\":\"identifier\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"}]},{\"type\":\"error\",\"name\":\"Invalid_Program_Identifier\",\"inputs\":[{\"name\":\"zkCoProcessor\",\"type\":\"uint8\",\"internalType\":\"enumZkCoProcessorType\"},{\"name\":\"identifier\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"}]},{\"type\":\"error\",\"name\":\"NewOwnerIsZeroAddress\",\"inputs\":[]},{\"type\":\"error\",\"name\":\"NoHandoverRequest\",\"inputs\":[]},{\"type\":\"error\",\"name\":\"Unauthorized\",\"inputs\":[]},{\"type\":\"error\",\"name\":\"Unknown_Zk_Coprocessor\",\"inputs\":[]},{\"type\":\"error\",\"name\":\"ZK_Route_Frozen\",\"inputs\":[{\"name\":\"zkCoProcessor\",\"type\":\"uint8\",\"internalType\":\"enumZkCoProcessorType\"},{\"name\":\"selector\",\"type\":\"bytes4\",\"internalType\":\"bytes4\"}]}]",
}

// SEVAgentAttestationABI is the input ABI used to generate the binding from.
// Deprecated: Use SEVAgentAttestationMetaData.ABI instead.
var SEVAgentAttestationABI = SEVAgentAttestationMetaData.ABI

// SEVAgentAttestation is an auto generated Go binding around an Ethereum contract.
type SEVAgentAttestation struct {
	SEVAgentAttestationCaller     // Read-only binding to the contract
	SEVAgentAttestationTransactor // Write-only binding to the contract
	SEVAgentAttestationFilterer   // Log filterer for contract events
}

// SEVAgentAttestationCaller is an auto generated read-only Go binding around an Ethereum contract.
type SEVAgentAttestationCaller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// SEVAgentAttestationTransactor is an auto generated write-only Go binding around an Ethereum contract.
type SEVAgentAttestationTransactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// SEVAgentAttestationFilterer is an auto generated log filtering Go binding around an Ethereum contract events.
type SEVAgentAttestationFilterer struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// SEVAgentAttestationSession is an auto generated Go binding around an Ethereum contract,
// with pre-set call and transact options.
type SEVAgentAttestationSession struct {
	Contract     *SEVAgentAttestation // Generic contract binding to set the session for
	CallOpts     bind.CallOpts        // Call options to use throughout this session
	TransactOpts bind.TransactOpts    // Transaction auth options to use throughout this session
}

// SEVAgentAttestationCallerSession is an auto generated read-only Go binding around an Ethereum contract,
// with pre-set call options.
type SEVAgentAttestationCallerSession struct {
	Contract *SEVAgentAttestationCaller // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts              // Call options to use throughout this session
}

// SEVAgentAttestationTransactorSession is an auto generated write-only Go binding around an Ethereum contract,
// with pre-set transact options.
type SEVAgentAttestationTransactorSession struct {
	Contract     *SEVAgentAttestationTransactor // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts              // Transaction auth options to use throughout this session
}

// SEVAgentAttestationRaw is an auto generated low-level Go binding around an Ethereum contract.
type SEVAgentAttestationRaw struct {
	Contract *SEVAgentAttestation // Generic contract binding to access the raw methods on
}

// SEVAgentAttestationCallerRaw is an auto generated low-level read-only Go binding around an Ethereum contract.
type SEVAgentAttestationCallerRaw struct {
	Contract *SEVAgentAttestationCaller // Generic read-only contract binding to access the raw methods on
}

// SEVAgentAttestationTransactorRaw is an auto generated low-level write-only Go binding around an Ethereum contract.
type SEVAgentAttestationTransactorRaw struct {
	Contract *SEVAgentAttestationTransactor // Generic write-only contract binding to access the raw methods on
}

// NewSEVAgentAttestation creates a new instance of SEVAgentAttestation, bound to a specific deployed contract.
func NewSEVAgentAttestation(address common.Address, backend bind.ContractBackend) (*SEVAgentAttestation, error) {
	contract, err := bindSEVAgentAttestation(address, backend, backend, backend)
	if err != nil {
		return nil, err
	}
	return &SEVAgentAttestation{SEVAgentAttestationCaller: SEVAgentAttestationCaller{contract: contract}, SEVAgentAttestationTransactor: SEVAgentAttestationTransactor{contract: contract}, SEVAgentAttestationFilterer: SEVAgentAttestationFilterer{contract: contract}}, nil
}

// NewSEVAgentAttestationCaller creates a new read-only instance of SEVAgentAttestation, bound to a specific deployed contract.
func NewSEVAgentAttestationCaller(address common.Address, caller bind.ContractCaller) (*SEVAgentAttestationCaller, error) {
	contract, err := bindSEVAgentAttestation(address, caller, nil, nil)
	if err != nil {
		return nil, err
	}
	return &SEVAgentAttestationCaller{contract: contract}, nil
}

// NewSEVAgentAttestationTransactor creates a new write-only instance of SEVAgentAttestation, bound to a specific deployed contract.
func NewSEVAgentAttestationTransactor(address common.Address, transactor bind.ContractTransactor) (*SEVAgentAttestationTransactor, error) {
	contract, err := bindSEVAgentAttestation(address, nil, transactor, nil)
	if err != nil {
		return nil, err
	}
	return &SEVAgentAttestationTransactor{contract: contract}, nil
}

// NewSEVAgentAttestationFilterer creates a new log filterer instance of SEVAgentAttestation, bound to a specific deployed contract.
func NewSEVAgentAttestationFilterer(address common.Address, filterer bind.ContractFilterer) (*SEVAgentAttestationFilterer, error) {
	contract, err := bindSEVAgentAttestation(address, nil, nil, filterer)
	if err != nil {
		return nil, err
	}
	return &SEVAgentAttestationFilterer{contract: contract}, nil
}

// bindSEVAgentAttestation binds a generic wrapper to an already deployed contract.
func bindSEVAgentAttestation(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor, filterer bind.ContractFilterer) (*bind.BoundContract, error) {
	parsed, err := SEVAgentAttestationMetaData.GetAbi()
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, *parsed, caller, transactor, filterer), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_SEVAgentAttestation *SEVAgentAttestationRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _SEVAgentAttestation.Contract.SEVAgentAttestationCaller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_SEVAgentAttestation *SEVAgentAttestationRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _SEVAgentAttestation.Contract.SEVAgentAttestationTransactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_SEVAgentAttestation *SEVAgentAttestationRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _SEVAgentAttestation.Contract.SEVAgentAttestationTransactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_SEVAgentAttestation *SEVAgentAttestationCallerRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _SEVAgentAttestation.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_SEVAgentAttestation *SEVAgentAttestationTransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _SEVAgentAttestation.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_SEVAgentAttestation *SEVAgentAttestationTransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _SEVAgentAttestation.Contract.contract.Transact(opts, method, params...)
}

// CheckTrustedIntermediateCerts is a free data retrieval call binding the contract method 0x5ef62335.
//
// Solidity: function checkTrustedIntermediateCerts(uint8[] processorModels, bytes32[][] reportCerts) view returns(uint8[])
func (_SEVAgentAttestation *SEVAgentAttestationCaller) CheckTrustedIntermediateCerts(opts *bind.CallOpts, processorModels []uint8, reportCerts [][][32]byte) ([]uint8, error) {
	var out []interface{}
	err := _SEVAgentAttestation.contract.Call(opts, &out, "checkTrustedIntermediateCerts", processorModels, reportCerts)

	if err != nil {
		return *new([]uint8), err
	}

	out0 := *abi.ConvertType(out[0], new([]uint8)).(*[]uint8)

	return out0, err

}

// CheckTrustedIntermediateCerts is a free data retrieval call binding the contract method 0x5ef62335.
//
// Solidity: function checkTrustedIntermediateCerts(uint8[] processorModels, bytes32[][] reportCerts) view returns(uint8[])
func (_SEVAgentAttestation *SEVAgentAttestationSession) CheckTrustedIntermediateCerts(processorModels []uint8, reportCerts [][][32]byte) ([]uint8, error) {
	return _SEVAgentAttestation.Contract.CheckTrustedIntermediateCerts(&_SEVAgentAttestation.CallOpts, processorModels, reportCerts)
}

// CheckTrustedIntermediateCerts is a free data retrieval call binding the contract method 0x5ef62335.
//
// Solidity: function checkTrustedIntermediateCerts(uint8[] processorModels, bytes32[][] reportCerts) view returns(uint8[])
func (_SEVAgentAttestation *SEVAgentAttestationCallerSession) CheckTrustedIntermediateCerts(processorModels []uint8, reportCerts [][][32]byte) ([]uint8, error) {
	return _SEVAgentAttestation.Contract.CheckTrustedIntermediateCerts(&_SEVAgentAttestation.CallOpts, processorModels, reportCerts)
}

// MaxTimeDiff is a free data retrieval call binding the contract method 0x369855e6.
//
// Solidity: function maxTimeDiff() view returns(uint64)
func (_SEVAgentAttestation *SEVAgentAttestationCaller) MaxTimeDiff(opts *bind.CallOpts) (uint64, error) {
	var out []interface{}
	err := _SEVAgentAttestation.contract.Call(opts, &out, "maxTimeDiff")

	if err != nil {
		return *new(uint64), err
	}

	out0 := *abi.ConvertType(out[0], new(uint64)).(*uint64)

	return out0, err

}

// MaxTimeDiff is a free data retrieval call binding the contract method 0x369855e6.
//
// Solidity: function maxTimeDiff() view returns(uint64)
func (_SEVAgentAttestation *SEVAgentAttestationSession) MaxTimeDiff() (uint64, error) {
	return _SEVAgentAttestation.Contract.MaxTimeDiff(&_SEVAgentAttestation.CallOpts)
}

// MaxTimeDiff is a free data retrieval call binding the contract method 0x369855e6.
//
// Solidity: function maxTimeDiff() view returns(uint64)
func (_SEVAgentAttestation *SEVAgentAttestationCallerSession) MaxTimeDiff() (uint64, error) {
	return _SEVAgentAttestation.Contract.MaxTimeDiff(&_SEVAgentAttestation.CallOpts)
}

// Owner is a free data retrieval call binding the contract method 0x8da5cb5b.
//
// Solidity: function owner() view returns(address result)
func (_SEVAgentAttestation *SEVAgentAttestationCaller) Owner(opts *bind.CallOpts) (common.Address, error) {
	var out []interface{}
	err := _SEVAgentAttestation.contract.Call(opts, &out, "owner")

	if err != nil {
		return *new(common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new(common.Address)).(*common.Address)

	return out0, err

}

// Owner is a free data retrieval call binding the contract method 0x8da5cb5b.
//
// Solidity: function owner() view returns(address result)
func (_SEVAgentAttestation *SEVAgentAttestationSession) Owner() (common.Address, error) {
	return _SEVAgentAttestation.Contract.Owner(&_SEVAgentAttestation.CallOpts)
}

// Owner is a free data retrieval call binding the contract method 0x8da5cb5b.
//
// Solidity: function owner() view returns(address result)
func (_SEVAgentAttestation *SEVAgentAttestationCallerSession) Owner() (common.Address, error) {
	return _SEVAgentAttestation.Contract.Owner(&_SEVAgentAttestation.CallOpts)
}

// OwnershipHandoverExpiresAt is a free data retrieval call binding the contract method 0xfee81cf4.
//
// Solidity: function ownershipHandoverExpiresAt(address pendingOwner) view returns(uint256 result)
func (_SEVAgentAttestation *SEVAgentAttestationCaller) OwnershipHandoverExpiresAt(opts *bind.CallOpts, pendingOwner common.Address) (*big.Int, error) {
	var out []interface{}
	err := _SEVAgentAttestation.contract.Call(opts, &out, "ownershipHandoverExpiresAt", pendingOwner)

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// OwnershipHandoverExpiresAt is a free data retrieval call binding the contract method 0xfee81cf4.
//
// Solidity: function ownershipHandoverExpiresAt(address pendingOwner) view returns(uint256 result)
func (_SEVAgentAttestation *SEVAgentAttestationSession) OwnershipHandoverExpiresAt(pendingOwner common.Address) (*big.Int, error) {
	return _SEVAgentAttestation.Contract.OwnershipHandoverExpiresAt(&_SEVAgentAttestation.CallOpts, pendingOwner)
}

// OwnershipHandoverExpiresAt is a free data retrieval call binding the contract method 0xfee81cf4.
//
// Solidity: function ownershipHandoverExpiresAt(address pendingOwner) view returns(uint256 result)
func (_SEVAgentAttestation *SEVAgentAttestationCallerSession) OwnershipHandoverExpiresAt(pendingOwner common.Address) (*big.Int, error) {
	return _SEVAgentAttestation.Contract.OwnershipHandoverExpiresAt(&_SEVAgentAttestation.CallOpts, pendingOwner)
}

// ProgramIdentifier is a free data retrieval call binding the contract method 0x3043d2b1.
//
// Solidity: function programIdentifier(uint8 zkCoProcessorType) view returns(bytes32)
func (_SEVAgentAttestation *SEVAgentAttestationCaller) ProgramIdentifier(opts *bind.CallOpts, zkCoProcessorType uint8) ([32]byte, error) {
	var out []interface{}
	err := _SEVAgentAttestation.contract.Call(opts, &out, "programIdentifier", zkCoProcessorType)

	if err != nil {
		return *new([32]byte), err
	}

	out0 := *abi.ConvertType(out[0], new([32]byte)).(*[32]byte)

	return out0, err

}

// ProgramIdentifier is a free data retrieval call binding the contract method 0x3043d2b1.
//
// Solidity: function programIdentifier(uint8 zkCoProcessorType) view returns(bytes32)
func (_SEVAgentAttestation *SEVAgentAttestationSession) ProgramIdentifier(zkCoProcessorType uint8) ([32]byte, error) {
	return _SEVAgentAttestation.Contract.ProgramIdentifier(&_SEVAgentAttestation.CallOpts, zkCoProcessorType)
}

// ProgramIdentifier is a free data retrieval call binding the contract method 0x3043d2b1.
//
// Solidity: function programIdentifier(uint8 zkCoProcessorType) view returns(bytes32)
func (_SEVAgentAttestation *SEVAgentAttestationCallerSession) ProgramIdentifier(zkCoProcessorType uint8) ([32]byte, error) {
	return _SEVAgentAttestation.Contract.ProgramIdentifier(&_SEVAgentAttestation.CallOpts, zkCoProcessorType)
}

// ProgramIdentifiers is a free data retrieval call binding the contract method 0xa01859a2.
//
// Solidity: function programIdentifiers(uint8 zkCoProcessorType) view returns(bytes32[])
func (_SEVAgentAttestation *SEVAgentAttestationCaller) ProgramIdentifiers(opts *bind.CallOpts, zkCoProcessorType uint8) ([][32]byte, error) {
	var out []interface{}
	err := _SEVAgentAttestation.contract.Call(opts, &out, "programIdentifiers", zkCoProcessorType)

	if err != nil {
		return *new([][32]byte), err
	}

	out0 := *abi.ConvertType(out[0], new([][32]byte)).(*[][32]byte)

	return out0, err

}

// ProgramIdentifiers is a free data retrieval call binding the contract method 0xa01859a2.
//
// Solidity: function programIdentifiers(uint8 zkCoProcessorType) view returns(bytes32[])
func (_SEVAgentAttestation *SEVAgentAttestationSession) ProgramIdentifiers(zkCoProcessorType uint8) ([][32]byte, error) {
	return _SEVAgentAttestation.Contract.ProgramIdentifiers(&_SEVAgentAttestation.CallOpts, zkCoProcessorType)
}

// ProgramIdentifiers is a free data retrieval call binding the contract method 0xa01859a2.
//
// Solidity: function programIdentifiers(uint8 zkCoProcessorType) view returns(bytes32[])
func (_SEVAgentAttestation *SEVAgentAttestationCallerSession) ProgramIdentifiers(zkCoProcessorType uint8) ([][32]byte, error) {
	return _SEVAgentAttestation.Contract.ProgramIdentifiers(&_SEVAgentAttestation.CallOpts, zkCoProcessorType)
}

// RootCerts is a free data retrieval call binding the contract method 0x22204493.
//
// Solidity: function rootCerts(uint8 processorModel) view returns(bytes32)
func (_SEVAgentAttestation *SEVAgentAttestationCaller) RootCerts(opts *bind.CallOpts, processorModel uint8) ([32]byte, error) {
	var out []interface{}
	err := _SEVAgentAttestation.contract.Call(opts, &out, "rootCerts", processorModel)

	if err != nil {
		return *new([32]byte), err
	}

	out0 := *abi.ConvertType(out[0], new([32]byte)).(*[32]byte)

	return out0, err

}

// RootCerts is a free data retrieval call binding the contract method 0x22204493.
//
// Solidity: function rootCerts(uint8 processorModel) view returns(bytes32)
func (_SEVAgentAttestation *SEVAgentAttestationSession) RootCerts(processorModel uint8) ([32]byte, error) {
	return _SEVAgentAttestation.Contract.RootCerts(&_SEVAgentAttestation.CallOpts, processorModel)
}

// RootCerts is a free data retrieval call binding the contract method 0x22204493.
//
// Solidity: function rootCerts(uint8 processorModel) view returns(bytes32)
func (_SEVAgentAttestation *SEVAgentAttestationCallerSession) RootCerts(processorModel uint8) ([32]byte, error) {
	return _SEVAgentAttestation.Contract.RootCerts(&_SEVAgentAttestation.CallOpts, processorModel)
}

// TrustedIntermediateCerts is a free data retrieval call binding the contract method 0xdd4a471d.
//
// Solidity: function trustedIntermediateCerts(bytes32 trustedCertHash) view returns(bool)
func (_SEVAgentAttestation *SEVAgentAttestationCaller) TrustedIntermediateCerts(opts *bind.CallOpts, trustedCertHash [32]byte) (bool, error) {
	var out []interface{}
	err := _SEVAgentAttestation.contract.Call(opts, &out, "trustedIntermediateCerts", trustedCertHash)

	if err != nil {
		return *new(bool), err
	}

	out0 := *abi.ConvertType(out[0], new(bool)).(*bool)

	return out0, err

}

// TrustedIntermediateCerts is a free data retrieval call binding the contract method 0xdd4a471d.
//
// Solidity: function trustedIntermediateCerts(bytes32 trustedCertHash) view returns(bool)
func (_SEVAgentAttestation *SEVAgentAttestationSession) TrustedIntermediateCerts(trustedCertHash [32]byte) (bool, error) {
	return _SEVAgentAttestation.Contract.TrustedIntermediateCerts(&_SEVAgentAttestation.CallOpts, trustedCertHash)
}

// TrustedIntermediateCerts is a free data retrieval call binding the contract method 0xdd4a471d.
//
// Solidity: function trustedIntermediateCerts(bytes32 trustedCertHash) view returns(bool)
func (_SEVAgentAttestation *SEVAgentAttestationCallerSession) TrustedIntermediateCerts(trustedCertHash [32]byte) (bool, error) {
	return _SEVAgentAttestation.Contract.TrustedIntermediateCerts(&_SEVAgentAttestation.CallOpts, trustedCertHash)
}

// ZkVerifier is a free data retrieval call binding the contract method 0x8355ec6c.
//
// Solidity: function zkVerifier(uint8 zkCoProcessorType) view returns(address)
func (_SEVAgentAttestation *SEVAgentAttestationCaller) ZkVerifier(opts *bind.CallOpts, zkCoProcessorType uint8) (common.Address, error) {
	var out []interface{}
	err := _SEVAgentAttestation.contract.Call(opts, &out, "zkVerifier", zkCoProcessorType)

	if err != nil {
		return *new(common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new(common.Address)).(*common.Address)

	return out0, err

}

// ZkVerifier is a free data retrieval call binding the contract method 0x8355ec6c.
//
// Solidity: function zkVerifier(uint8 zkCoProcessorType) view returns(address)
func (_SEVAgentAttestation *SEVAgentAttestationSession) ZkVerifier(zkCoProcessorType uint8) (common.Address, error) {
	return _SEVAgentAttestation.Contract.ZkVerifier(&_SEVAgentAttestation.CallOpts, zkCoProcessorType)
}

// ZkVerifier is a free data retrieval call binding the contract method 0x8355ec6c.
//
// Solidity: function zkVerifier(uint8 zkCoProcessorType) view returns(address)
func (_SEVAgentAttestation *SEVAgentAttestationCallerSession) ZkVerifier(zkCoProcessorType uint8) (common.Address, error) {
	return _SEVAgentAttestation.Contract.ZkVerifier(&_SEVAgentAttestation.CallOpts, zkCoProcessorType)
}

// ZkVerifier0 is a free data retrieval call binding the contract method 0xe9776c46.
//
// Solidity: function zkVerifier(uint8 zkCoProcessorType, bytes4 selector) view returns(address)
func (_SEVAgentAttestation *SEVAgentAttestationCaller) ZkVerifier0(opts *bind.CallOpts, zkCoProcessorType uint8, selector [4]byte) (common.Address, error) {
	var out []interface{}
	err := _SEVAgentAttestation.contract.Call(opts, &out, "zkVerifier0", zkCoProcessorType, selector)

	if err != nil {
		return *new(common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new(common.Address)).(*common.Address)

	return out0, err

}

// ZkVerifier0 is a free data retrieval call binding the contract method 0xe9776c46.
//
// Solidity: function zkVerifier(uint8 zkCoProcessorType, bytes4 selector) view returns(address)
func (_SEVAgentAttestation *SEVAgentAttestationSession) ZkVerifier0(zkCoProcessorType uint8, selector [4]byte) (common.Address, error) {
	return _SEVAgentAttestation.Contract.ZkVerifier0(&_SEVAgentAttestation.CallOpts, zkCoProcessorType, selector)
}

// ZkVerifier0 is a free data retrieval call binding the contract method 0xe9776c46.
//
// Solidity: function zkVerifier(uint8 zkCoProcessorType, bytes4 selector) view returns(address)
func (_SEVAgentAttestation *SEVAgentAttestationCallerSession) ZkVerifier0(zkCoProcessorType uint8, selector [4]byte) (common.Address, error) {
	return _SEVAgentAttestation.Contract.ZkVerifier0(&_SEVAgentAttestation.CallOpts, zkCoProcessorType, selector)
}

// AddVerifyRoute is a paid mutator transaction binding the contract method 0x86546a49.
//
// Solidity: function addVerifyRoute(uint8 zkCoProcessor, bytes4 selector, address verifier) returns()
func (_SEVAgentAttestation *SEVAgentAttestationTransactor) AddVerifyRoute(opts *bind.TransactOpts, zkCoProcessor uint8, selector [4]byte, verifier common.Address) (*types.Transaction, error) {
	return _SEVAgentAttestation.contract.Transact(opts, "addVerifyRoute", zkCoProcessor, selector, verifier)
}

// AddVerifyRoute is a paid mutator transaction binding the contract method 0x86546a49.
//
// Solidity: function addVerifyRoute(uint8 zkCoProcessor, bytes4 selector, address verifier) returns()
func (_SEVAgentAttestation *SEVAgentAttestationSession) AddVerifyRoute(zkCoProcessor uint8, selector [4]byte, verifier common.Address) (*types.Transaction, error) {
	return _SEVAgentAttestation.Contract.AddVerifyRoute(&_SEVAgentAttestation.TransactOpts, zkCoProcessor, selector, verifier)
}

// AddVerifyRoute is a paid mutator transaction binding the contract method 0x86546a49.
//
// Solidity: function addVerifyRoute(uint8 zkCoProcessor, bytes4 selector, address verifier) returns()
func (_SEVAgentAttestation *SEVAgentAttestationTransactorSession) AddVerifyRoute(zkCoProcessor uint8, selector [4]byte, verifier common.Address) (*types.Transaction, error) {
	return _SEVAgentAttestation.Contract.AddVerifyRoute(&_SEVAgentAttestation.TransactOpts, zkCoProcessor, selector, verifier)
}

// CancelOwnershipHandover is a paid mutator transaction binding the contract method 0x54d1f13d.
//
// Solidity: function cancelOwnershipHandover() payable returns()
func (_SEVAgentAttestation *SEVAgentAttestationTransactor) CancelOwnershipHandover(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _SEVAgentAttestation.contract.Transact(opts, "cancelOwnershipHandover")
}

// CancelOwnershipHandover is a paid mutator transaction binding the contract method 0x54d1f13d.
//
// Solidity: function cancelOwnershipHandover() payable returns()
func (_SEVAgentAttestation *SEVAgentAttestationSession) CancelOwnershipHandover() (*types.Transaction, error) {
	return _SEVAgentAttestation.Contract.CancelOwnershipHandover(&_SEVAgentAttestation.TransactOpts)
}

// CancelOwnershipHandover is a paid mutator transaction binding the contract method 0x54d1f13d.
//
// Solidity: function cancelOwnershipHandover() payable returns()
func (_SEVAgentAttestation *SEVAgentAttestationTransactorSession) CancelOwnershipHandover() (*types.Transaction, error) {
	return _SEVAgentAttestation.Contract.CancelOwnershipHandover(&_SEVAgentAttestation.TransactOpts)
}

// CompleteOwnershipHandover is a paid mutator transaction binding the contract method 0xf04e283e.
//
// Solidity: function completeOwnershipHandover(address pendingOwner) payable returns()
func (_SEVAgentAttestation *SEVAgentAttestationTransactor) CompleteOwnershipHandover(opts *bind.TransactOpts, pendingOwner common.Address) (*types.Transaction, error) {
	return _SEVAgentAttestation.contract.Transact(opts, "completeOwnershipHandover", pendingOwner)
}

// CompleteOwnershipHandover is a paid mutator transaction binding the contract method 0xf04e283e.
//
// Solidity: function completeOwnershipHandover(address pendingOwner) payable returns()
func (_SEVAgentAttestation *SEVAgentAttestationSession) CompleteOwnershipHandover(pendingOwner common.Address) (*types.Transaction, error) {
	return _SEVAgentAttestation.Contract.CompleteOwnershipHandover(&_SEVAgentAttestation.TransactOpts, pendingOwner)
}

// CompleteOwnershipHandover is a paid mutator transaction binding the contract method 0xf04e283e.
//
// Solidity: function completeOwnershipHandover(address pendingOwner) payable returns()
func (_SEVAgentAttestation *SEVAgentAttestationTransactorSession) CompleteOwnershipHandover(pendingOwner common.Address) (*types.Transaction, error) {
	return _SEVAgentAttestation.Contract.CompleteOwnershipHandover(&_SEVAgentAttestation.TransactOpts, pendingOwner)
}

// FreezeVerifyRoute is a paid mutator transaction binding the contract method 0x63cd3456.
//
// Solidity: function freezeVerifyRoute(uint8 zkCoProcessor, bytes4 selector) returns()
func (_SEVAgentAttestation *SEVAgentAttestationTransactor) FreezeVerifyRoute(opts *bind.TransactOpts, zkCoProcessor uint8, selector [4]byte) (*types.Transaction, error) {
	return _SEVAgentAttestation.contract.Transact(opts, "freezeVerifyRoute", zkCoProcessor, selector)
}

// FreezeVerifyRoute is a paid mutator transaction binding the contract method 0x63cd3456.
//
// Solidity: function freezeVerifyRoute(uint8 zkCoProcessor, bytes4 selector) returns()
func (_SEVAgentAttestation *SEVAgentAttestationSession) FreezeVerifyRoute(zkCoProcessor uint8, selector [4]byte) (*types.Transaction, error) {
	return _SEVAgentAttestation.Contract.FreezeVerifyRoute(&_SEVAgentAttestation.TransactOpts, zkCoProcessor, selector)
}

// FreezeVerifyRoute is a paid mutator transaction binding the contract method 0x63cd3456.
//
// Solidity: function freezeVerifyRoute(uint8 zkCoProcessor, bytes4 selector) returns()
func (_SEVAgentAttestation *SEVAgentAttestationTransactorSession) FreezeVerifyRoute(zkCoProcessor uint8, selector [4]byte) (*types.Transaction, error) {
	return _SEVAgentAttestation.Contract.FreezeVerifyRoute(&_SEVAgentAttestation.TransactOpts, zkCoProcessor, selector)
}

// RemoveProgramIdentifier is a paid mutator transaction binding the contract method 0xb6bcccf1.
//
// Solidity: function removeProgramIdentifier(uint8 zkCoProcessor, bytes32 identifier) returns()
func (_SEVAgentAttestation *SEVAgentAttestationTransactor) RemoveProgramIdentifier(opts *bind.TransactOpts, zkCoProcessor uint8, identifier [32]byte) (*types.Transaction, error) {
	return _SEVAgentAttestation.contract.Transact(opts, "removeProgramIdentifier", zkCoProcessor, identifier)
}

// RemoveProgramIdentifier is a paid mutator transaction binding the contract method 0xb6bcccf1.
//
// Solidity: function removeProgramIdentifier(uint8 zkCoProcessor, bytes32 identifier) returns()
func (_SEVAgentAttestation *SEVAgentAttestationSession) RemoveProgramIdentifier(zkCoProcessor uint8, identifier [32]byte) (*types.Transaction, error) {
	return _SEVAgentAttestation.Contract.RemoveProgramIdentifier(&_SEVAgentAttestation.TransactOpts, zkCoProcessor, identifier)
}

// RemoveProgramIdentifier is a paid mutator transaction binding the contract method 0xb6bcccf1.
//
// Solidity: function removeProgramIdentifier(uint8 zkCoProcessor, bytes32 identifier) returns()
func (_SEVAgentAttestation *SEVAgentAttestationTransactorSession) RemoveProgramIdentifier(zkCoProcessor uint8, identifier [32]byte) (*types.Transaction, error) {
	return _SEVAgentAttestation.Contract.RemoveProgramIdentifier(&_SEVAgentAttestation.TransactOpts, zkCoProcessor, identifier)
}

// RenounceOwnership is a paid mutator transaction binding the contract method 0x715018a6.
//
// Solidity: function renounceOwnership() payable returns()
func (_SEVAgentAttestation *SEVAgentAttestationTransactor) RenounceOwnership(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _SEVAgentAttestation.contract.Transact(opts, "renounceOwnership")
}

// RenounceOwnership is a paid mutator transaction binding the contract method 0x715018a6.
//
// Solidity: function renounceOwnership() payable returns()
func (_SEVAgentAttestation *SEVAgentAttestationSession) RenounceOwnership() (*types.Transaction, error) {
	return _SEVAgentAttestation.Contract.RenounceOwnership(&_SEVAgentAttestation.TransactOpts)
}

// RenounceOwnership is a paid mutator transaction binding the contract method 0x715018a6.
//
// Solidity: function renounceOwnership() payable returns()
func (_SEVAgentAttestation *SEVAgentAttestationTransactorSession) RenounceOwnership() (*types.Transaction, error) {
	return _SEVAgentAttestation.Contract.RenounceOwnership(&_SEVAgentAttestation.TransactOpts)
}

// RequestOwnershipHandover is a paid mutator transaction binding the contract method 0x25692962.
//
// Solidity: function requestOwnershipHandover() payable returns()
func (_SEVAgentAttestation *SEVAgentAttestationTransactor) RequestOwnershipHandover(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _SEVAgentAttestation.contract.Transact(opts, "requestOwnershipHandover")
}

// RequestOwnershipHandover is a paid mutator transaction binding the contract method 0x25692962.
//
// Solidity: function requestOwnershipHandover() payable returns()
func (_SEVAgentAttestation *SEVAgentAttestationSession) RequestOwnershipHandover() (*types.Transaction, error) {
	return _SEVAgentAttestation.Contract.RequestOwnershipHandover(&_SEVAgentAttestation.TransactOpts)
}

// RequestOwnershipHandover is a paid mutator transaction binding the contract method 0x25692962.
//
// Solidity: function requestOwnershipHandover() payable returns()
func (_SEVAgentAttestation *SEVAgentAttestationTransactorSession) RequestOwnershipHandover() (*types.Transaction, error) {
	return _SEVAgentAttestation.Contract.RequestOwnershipHandover(&_SEVAgentAttestation.TransactOpts)
}

// RevokeCertCache is a paid mutator transaction binding the contract method 0xc2ee91ab.
//
// Solidity: function revokeCertCache(bytes32 _certHash) returns()
func (_SEVAgentAttestation *SEVAgentAttestationTransactor) RevokeCertCache(opts *bind.TransactOpts, _certHash [32]byte) (*types.Transaction, error) {
	return _SEVAgentAttestation.contract.Transact(opts, "revokeCertCache", _certHash)
}

// RevokeCertCache is a paid mutator transaction binding the contract method 0xc2ee91ab.
//
// Solidity: function revokeCertCache(bytes32 _certHash) returns()
func (_SEVAgentAttestation *SEVAgentAttestationSession) RevokeCertCache(_certHash [32]byte) (*types.Transaction, error) {
	return _SEVAgentAttestation.Contract.RevokeCertCache(&_SEVAgentAttestation.TransactOpts, _certHash)
}

// RevokeCertCache is a paid mutator transaction binding the contract method 0xc2ee91ab.
//
// Solidity: function revokeCertCache(bytes32 _certHash) returns()
func (_SEVAgentAttestation *SEVAgentAttestationTransactorSession) RevokeCertCache(_certHash [32]byte) (*types.Transaction, error) {
	return _SEVAgentAttestation.Contract.RevokeCertCache(&_SEVAgentAttestation.TransactOpts, _certHash)
}

// SetMaxTimeDiff is a paid mutator transaction binding the contract method 0xe3f47695.
//
// Solidity: function setMaxTimeDiff(uint64 _maxTimeDiff) returns()
func (_SEVAgentAttestation *SEVAgentAttestationTransactor) SetMaxTimeDiff(opts *bind.TransactOpts, _maxTimeDiff uint64) (*types.Transaction, error) {
	return _SEVAgentAttestation.contract.Transact(opts, "setMaxTimeDiff", _maxTimeDiff)
}

// SetMaxTimeDiff is a paid mutator transaction binding the contract method 0xe3f47695.
//
// Solidity: function setMaxTimeDiff(uint64 _maxTimeDiff) returns()
func (_SEVAgentAttestation *SEVAgentAttestationSession) SetMaxTimeDiff(_maxTimeDiff uint64) (*types.Transaction, error) {
	return _SEVAgentAttestation.Contract.SetMaxTimeDiff(&_SEVAgentAttestation.TransactOpts, _maxTimeDiff)
}

// SetMaxTimeDiff is a paid mutator transaction binding the contract method 0xe3f47695.
//
// Solidity: function setMaxTimeDiff(uint64 _maxTimeDiff) returns()
func (_SEVAgentAttestation *SEVAgentAttestationTransactorSession) SetMaxTimeDiff(_maxTimeDiff uint64) (*types.Transaction, error) {
	return _SEVAgentAttestation.Contract.SetMaxTimeDiff(&_SEVAgentAttestation.TransactOpts, _maxTimeDiff)
}

// SetRootCert is a paid mutator transaction binding the contract method 0xc3c83ca4.
//
// Solidity: function setRootCert(uint8 _processorModel, bytes32 _rootCert) returns()
func (_SEVAgentAttestation *SEVAgentAttestationTransactor) SetRootCert(opts *bind.TransactOpts, _processorModel uint8, _rootCert [32]byte) (*types.Transaction, error) {
	return _SEVAgentAttestation.contract.Transact(opts, "setRootCert", _processorModel, _rootCert)
}

// SetRootCert is a paid mutator transaction binding the contract method 0xc3c83ca4.
//
// Solidity: function setRootCert(uint8 _processorModel, bytes32 _rootCert) returns()
func (_SEVAgentAttestation *SEVAgentAttestationSession) SetRootCert(_processorModel uint8, _rootCert [32]byte) (*types.Transaction, error) {
	return _SEVAgentAttestation.Contract.SetRootCert(&_SEVAgentAttestation.TransactOpts, _processorModel, _rootCert)
}

// SetRootCert is a paid mutator transaction binding the contract method 0xc3c83ca4.
//
// Solidity: function setRootCert(uint8 _processorModel, bytes32 _rootCert) returns()
func (_SEVAgentAttestation *SEVAgentAttestationTransactorSession) SetRootCert(_processorModel uint8, _rootCert [32]byte) (*types.Transaction, error) {
	return _SEVAgentAttestation.Contract.SetRootCert(&_SEVAgentAttestation.TransactOpts, _processorModel, _rootCert)
}

// SetZkConfiguration is a paid mutator transaction binding the contract method 0x25e11c75.
//
// Solidity: function setZkConfiguration(uint8 zkCoProcessor, (bytes32,address) config) returns()
func (_SEVAgentAttestation *SEVAgentAttestationTransactor) SetZkConfiguration(opts *bind.TransactOpts, zkCoProcessor uint8, config ZkCoProcessorConfig) (*types.Transaction, error) {
	return _SEVAgentAttestation.contract.Transact(opts, "setZkConfiguration", zkCoProcessor, config)
}

// SetZkConfiguration is a paid mutator transaction binding the contract method 0x25e11c75.
//
// Solidity: function setZkConfiguration(uint8 zkCoProcessor, (bytes32,address) config) returns()
func (_SEVAgentAttestation *SEVAgentAttestationSession) SetZkConfiguration(zkCoProcessor uint8, config ZkCoProcessorConfig) (*types.Transaction, error) {
	return _SEVAgentAttestation.Contract.SetZkConfiguration(&_SEVAgentAttestation.TransactOpts, zkCoProcessor, config)
}

// SetZkConfiguration is a paid mutator transaction binding the contract method 0x25e11c75.
//
// Solidity: function setZkConfiguration(uint8 zkCoProcessor, (bytes32,address) config) returns()
func (_SEVAgentAttestation *SEVAgentAttestationTransactorSession) SetZkConfiguration(zkCoProcessor uint8, config ZkCoProcessorConfig) (*types.Transaction, error) {
	return _SEVAgentAttestation.Contract.SetZkConfiguration(&_SEVAgentAttestation.TransactOpts, zkCoProcessor, config)
}

// TransferOwnership is a paid mutator transaction binding the contract method 0xf2fde38b.
//
// Solidity: function transferOwnership(address newOwner) payable returns()
func (_SEVAgentAttestation *SEVAgentAttestationTransactor) TransferOwnership(opts *bind.TransactOpts, newOwner common.Address) (*types.Transaction, error) {
	return _SEVAgentAttestation.contract.Transact(opts, "transferOwnership", newOwner)
}

// TransferOwnership is a paid mutator transaction binding the contract method 0xf2fde38b.
//
// Solidity: function transferOwnership(address newOwner) payable returns()
func (_SEVAgentAttestation *SEVAgentAttestationSession) TransferOwnership(newOwner common.Address) (*types.Transaction, error) {
	return _SEVAgentAttestation.Contract.TransferOwnership(&_SEVAgentAttestation.TransactOpts, newOwner)
}

// TransferOwnership is a paid mutator transaction binding the contract method 0xf2fde38b.
//
// Solidity: function transferOwnership(address newOwner) payable returns()
func (_SEVAgentAttestation *SEVAgentAttestationTransactorSession) TransferOwnership(newOwner common.Address) (*types.Transaction, error) {
	return _SEVAgentAttestation.Contract.TransferOwnership(&_SEVAgentAttestation.TransactOpts, newOwner)
}

// UpdateProgramIdentifier is a paid mutator transaction binding the contract method 0x5786be89.
//
// Solidity: function updateProgramIdentifier(uint8 zkCoProcessor, bytes32 identifier) returns()
func (_SEVAgentAttestation *SEVAgentAttestationTransactor) UpdateProgramIdentifier(opts *bind.TransactOpts, zkCoProcessor uint8, identifier [32]byte) (*types.Transaction, error) {
	return _SEVAgentAttestation.contract.Transact(opts, "updateProgramIdentifier", zkCoProcessor, identifier)
}

// UpdateProgramIdentifier is a paid mutator transaction binding the contract method 0x5786be89.
//
// Solidity: function updateProgramIdentifier(uint8 zkCoProcessor, bytes32 identifier) returns()
func (_SEVAgentAttestation *SEVAgentAttestationSession) UpdateProgramIdentifier(zkCoProcessor uint8, identifier [32]byte) (*types.Transaction, error) {
	return _SEVAgentAttestation.Contract.UpdateProgramIdentifier(&_SEVAgentAttestation.TransactOpts, zkCoProcessor, identifier)
}

// UpdateProgramIdentifier is a paid mutator transaction binding the contract method 0x5786be89.
//
// Solidity: function updateProgramIdentifier(uint8 zkCoProcessor, bytes32 identifier) returns()
func (_SEVAgentAttestation *SEVAgentAttestationTransactorSession) UpdateProgramIdentifier(zkCoProcessor uint8, identifier [32]byte) (*types.Transaction, error) {
	return _SEVAgentAttestation.Contract.UpdateProgramIdentifier(&_SEVAgentAttestation.TransactOpts, zkCoProcessor, identifier)
}

// VerifyAndAttestWithZKProof is a paid mutator transaction binding the contract method 0x41324bd9.
//
// Solidity: function verifyAndAttestWithZKProof(bytes output, uint8 zkCoprocessor, bytes32 identifier, bytes proofBytes) returns((uint8,uint64,uint8,bytes,bytes32[],uint160[],uint8) parsed)
func (_SEVAgentAttestation *SEVAgentAttestationTransactor) VerifyAndAttestWithZKProof(opts *bind.TransactOpts, output []byte, zkCoprocessor uint8, identifier [32]byte, proofBytes []byte) (*types.Transaction, error) {
	return _SEVAgentAttestation.contract.Transact(opts, "verifyAndAttestWithZKProof", output, zkCoprocessor, identifier, proofBytes)
}

// VerifyAndAttestWithZKProof is a paid mutator transaction binding the contract method 0x41324bd9.
//
// Solidity: function verifyAndAttestWithZKProof(bytes output, uint8 zkCoprocessor, bytes32 identifier, bytes proofBytes) returns((uint8,uint64,uint8,bytes,bytes32[],uint160[],uint8) parsed)
func (_SEVAgentAttestation *SEVAgentAttestationSession) VerifyAndAttestWithZKProof(output []byte, zkCoprocessor uint8, identifier [32]byte, proofBytes []byte) (*types.Transaction, error) {
	return _SEVAgentAttestation.Contract.VerifyAndAttestWithZKProof(&_SEVAgentAttestation.TransactOpts, output, zkCoprocessor, identifier, proofBytes)
}

// VerifyAndAttestWithZKProof is a paid mutator transaction binding the contract method 0x41324bd9.
//
// Solidity: function verifyAndAttestWithZKProof(bytes output, uint8 zkCoprocessor, bytes32 identifier, bytes proofBytes) returns((uint8,uint64,uint8,bytes,bytes32[],uint160[],uint8) parsed)
func (_SEVAgentAttestation *SEVAgentAttestationTransactorSession) VerifyAndAttestWithZKProof(output []byte, zkCoprocessor uint8, identifier [32]byte, proofBytes []byte) (*types.Transaction, error) {
	return _SEVAgentAttestation.Contract.VerifyAndAttestWithZKProof(&_SEVAgentAttestation.TransactOpts, output, zkCoprocessor, identifier, proofBytes)
}

// VerifyAndAttestWithZKProof0 is a paid mutator transaction binding the contract method 0x57859ce0.
//
// Solidity: function verifyAndAttestWithZKProof(bytes output, uint8 zkCoprocessor, bytes proofBytes) returns((uint8,uint64,uint8,bytes,bytes32[],uint160[],uint8) parsed)
func (_SEVAgentAttestation *SEVAgentAttestationTransactor) VerifyAndAttestWithZKProof0(opts *bind.TransactOpts, output []byte, zkCoprocessor uint8, proofBytes []byte) (*types.Transaction, error) {
	return _SEVAgentAttestation.contract.Transact(opts, "verifyAndAttestWithZKProof0", output, zkCoprocessor, proofBytes)
}

// VerifyAndAttestWithZKProof0 is a paid mutator transaction binding the contract method 0x57859ce0.
//
// Solidity: function verifyAndAttestWithZKProof(bytes output, uint8 zkCoprocessor, bytes proofBytes) returns((uint8,uint64,uint8,bytes,bytes32[],uint160[],uint8) parsed)
func (_SEVAgentAttestation *SEVAgentAttestationSession) VerifyAndAttestWithZKProof0(output []byte, zkCoprocessor uint8, proofBytes []byte) (*types.Transaction, error) {
	return _SEVAgentAttestation.Contract.VerifyAndAttestWithZKProof0(&_SEVAgentAttestation.TransactOpts, output, zkCoprocessor, proofBytes)
}

// VerifyAndAttestWithZKProof0 is a paid mutator transaction binding the contract method 0x57859ce0.
//
// Solidity: function verifyAndAttestWithZKProof(bytes output, uint8 zkCoprocessor, bytes proofBytes) returns((uint8,uint64,uint8,bytes,bytes32[],uint160[],uint8) parsed)
func (_SEVAgentAttestation *SEVAgentAttestationTransactorSession) VerifyAndAttestWithZKProof0(output []byte, zkCoprocessor uint8, proofBytes []byte) (*types.Transaction, error) {
	return _SEVAgentAttestation.Contract.VerifyAndAttestWithZKProof0(&_SEVAgentAttestation.TransactOpts, output, zkCoprocessor, proofBytes)
}

// SEVAgentAttestationAttestationSubmittedIterator is returned from FilterAttestationSubmitted and is used to iterate over the raw logs and unpacked data for AttestationSubmitted events raised by the SEVAgentAttestation contract.
type SEVAgentAttestationAttestationSubmittedIterator struct {
	Event *SEVAgentAttestationAttestationSubmitted // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *SEVAgentAttestationAttestationSubmittedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(SEVAgentAttestationAttestationSubmitted)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(SEVAgentAttestationAttestationSubmitted)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *SEVAgentAttestationAttestationSubmittedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *SEVAgentAttestationAttestationSubmittedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// SEVAgentAttestationAttestationSubmitted represents a AttestationSubmitted event raised by the SEVAgentAttestation contract.
type SEVAgentAttestationAttestationSubmitted struct {
	Result        uint8
	ZkCoProcessor uint8
	Output        []byte
	Raw           types.Log // Blockchain specific contextual infos
}

// FilterAttestationSubmitted is a free log retrieval operation binding the contract event 0x34d71c5db80e3c1db53f6d245503c531894f694aa26c7a967adf77167b126036.
//
// Solidity: event AttestationSubmitted(uint8 result, uint8 zkCoProcessor, bytes output)
func (_SEVAgentAttestation *SEVAgentAttestationFilterer) FilterAttestationSubmitted(opts *bind.FilterOpts) (*SEVAgentAttestationAttestationSubmittedIterator, error) {

	logs, sub, err := _SEVAgentAttestation.contract.FilterLogs(opts, "AttestationSubmitted")
	if err != nil {
		return nil, err
	}
	return &SEVAgentAttestationAttestationSubmittedIterator{contract: _SEVAgentAttestation.contract, event: "AttestationSubmitted", logs: logs, sub: sub}, nil
}

// WatchAttestationSubmitted is a free log subscription operation binding the contract event 0x34d71c5db80e3c1db53f6d245503c531894f694aa26c7a967adf77167b126036.
//
// Solidity: event AttestationSubmitted(uint8 result, uint8 zkCoProcessor, bytes output)
func (_SEVAgentAttestation *SEVAgentAttestationFilterer) WatchAttestationSubmitted(opts *bind.WatchOpts, sink chan<- *SEVAgentAttestationAttestationSubmitted) (event.Subscription, error) {

	logs, sub, err := _SEVAgentAttestation.contract.WatchLogs(opts, "AttestationSubmitted")
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(SEVAgentAttestationAttestationSubmitted)
				if err := _SEVAgentAttestation.contract.UnpackLog(event, "AttestationSubmitted", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseAttestationSubmitted is a log parse operation binding the contract event 0x34d71c5db80e3c1db53f6d245503c531894f694aa26c7a967adf77167b126036.
//
// Solidity: event AttestationSubmitted(uint8 result, uint8 zkCoProcessor, bytes output)
func (_SEVAgentAttestation *SEVAgentAttestationFilterer) ParseAttestationSubmitted(log types.Log) (*SEVAgentAttestationAttestationSubmitted, error) {
	event := new(SEVAgentAttestationAttestationSubmitted)
	if err := _SEVAgentAttestation.contract.UnpackLog(event, "AttestationSubmitted", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// SEVAgentAttestationOwnershipHandoverCanceledIterator is returned from FilterOwnershipHandoverCanceled and is used to iterate over the raw logs and unpacked data for OwnershipHandoverCanceled events raised by the SEVAgentAttestation contract.
type SEVAgentAttestationOwnershipHandoverCanceledIterator struct {
	Event *SEVAgentAttestationOwnershipHandoverCanceled // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *SEVAgentAttestationOwnershipHandoverCanceledIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(SEVAgentAttestationOwnershipHandoverCanceled)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(SEVAgentAttestationOwnershipHandoverCanceled)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *SEVAgentAttestationOwnershipHandoverCanceledIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *SEVAgentAttestationOwnershipHandoverCanceledIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// SEVAgentAttestationOwnershipHandoverCanceled represents a OwnershipHandoverCanceled event raised by the SEVAgentAttestation contract.
type SEVAgentAttestationOwnershipHandoverCanceled struct {
	PendingOwner common.Address
	Raw          types.Log // Blockchain specific contextual infos
}

// FilterOwnershipHandoverCanceled is a free log retrieval operation binding the contract event 0xfa7b8eab7da67f412cc9575ed43464468f9bfbae89d1675917346ca6d8fe3c92.
//
// Solidity: event OwnershipHandoverCanceled(address indexed pendingOwner)
func (_SEVAgentAttestation *SEVAgentAttestationFilterer) FilterOwnershipHandoverCanceled(opts *bind.FilterOpts, pendingOwner []common.Address) (*SEVAgentAttestationOwnershipHandoverCanceledIterator, error) {

	var pendingOwnerRule []interface{}
	for _, pendingOwnerItem := range pendingOwner {
		pendingOwnerRule = append(pendingOwnerRule, pendingOwnerItem)
	}

	logs, sub, err := _SEVAgentAttestation.contract.FilterLogs(opts, "OwnershipHandoverCanceled", pendingOwnerRule)
	if err != nil {
		return nil, err
	}
	return &SEVAgentAttestationOwnershipHandoverCanceledIterator{contract: _SEVAgentAttestation.contract, event: "OwnershipHandoverCanceled", logs: logs, sub: sub}, nil
}

// WatchOwnershipHandoverCanceled is a free log subscription operation binding the contract event 0xfa7b8eab7da67f412cc9575ed43464468f9bfbae89d1675917346ca6d8fe3c92.
//
// Solidity: event OwnershipHandoverCanceled(address indexed pendingOwner)
func (_SEVAgentAttestation *SEVAgentAttestationFilterer) WatchOwnershipHandoverCanceled(opts *bind.WatchOpts, sink chan<- *SEVAgentAttestationOwnershipHandoverCanceled, pendingOwner []common.Address) (event.Subscription, error) {

	var pendingOwnerRule []interface{}
	for _, pendingOwnerItem := range pendingOwner {
		pendingOwnerRule = append(pendingOwnerRule, pendingOwnerItem)
	}

	logs, sub, err := _SEVAgentAttestation.contract.WatchLogs(opts, "OwnershipHandoverCanceled", pendingOwnerRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(SEVAgentAttestationOwnershipHandoverCanceled)
				if err := _SEVAgentAttestation.contract.UnpackLog(event, "OwnershipHandoverCanceled", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseOwnershipHandoverCanceled is a log parse operation binding the contract event 0xfa7b8eab7da67f412cc9575ed43464468f9bfbae89d1675917346ca6d8fe3c92.
//
// Solidity: event OwnershipHandoverCanceled(address indexed pendingOwner)
func (_SEVAgentAttestation *SEVAgentAttestationFilterer) ParseOwnershipHandoverCanceled(log types.Log) (*SEVAgentAttestationOwnershipHandoverCanceled, error) {
	event := new(SEVAgentAttestationOwnershipHandoverCanceled)
	if err := _SEVAgentAttestation.contract.UnpackLog(event, "OwnershipHandoverCanceled", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// SEVAgentAttestationOwnershipHandoverRequestedIterator is returned from FilterOwnershipHandoverRequested and is used to iterate over the raw logs and unpacked data for OwnershipHandoverRequested events raised by the SEVAgentAttestation contract.
type SEVAgentAttestationOwnershipHandoverRequestedIterator struct {
	Event *SEVAgentAttestationOwnershipHandoverRequested // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *SEVAgentAttestationOwnershipHandoverRequestedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(SEVAgentAttestationOwnershipHandoverRequested)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(SEVAgentAttestationOwnershipHandoverRequested)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *SEVAgentAttestationOwnershipHandoverRequestedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *SEVAgentAttestationOwnershipHandoverRequestedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// SEVAgentAttestationOwnershipHandoverRequested represents a OwnershipHandoverRequested event raised by the SEVAgentAttestation contract.
type SEVAgentAttestationOwnershipHandoverRequested struct {
	PendingOwner common.Address
	Raw          types.Log // Blockchain specific contextual infos
}

// FilterOwnershipHandoverRequested is a free log retrieval operation binding the contract event 0xdbf36a107da19e49527a7176a1babf963b4b0ff8cde35ee35d6cd8f1f9ac7e1d.
//
// Solidity: event OwnershipHandoverRequested(address indexed pendingOwner)
func (_SEVAgentAttestation *SEVAgentAttestationFilterer) FilterOwnershipHandoverRequested(opts *bind.FilterOpts, pendingOwner []common.Address) (*SEVAgentAttestationOwnershipHandoverRequestedIterator, error) {

	var pendingOwnerRule []interface{}
	for _, pendingOwnerItem := range pendingOwner {
		pendingOwnerRule = append(pendingOwnerRule, pendingOwnerItem)
	}

	logs, sub, err := _SEVAgentAttestation.contract.FilterLogs(opts, "OwnershipHandoverRequested", pendingOwnerRule)
	if err != nil {
		return nil, err
	}
	return &SEVAgentAttestationOwnershipHandoverRequestedIterator{contract: _SEVAgentAttestation.contract, event: "OwnershipHandoverRequested", logs: logs, sub: sub}, nil
}

// WatchOwnershipHandoverRequested is a free log subscription operation binding the contract event 0xdbf36a107da19e49527a7176a1babf963b4b0ff8cde35ee35d6cd8f1f9ac7e1d.
//
// Solidity: event OwnershipHandoverRequested(address indexed pendingOwner)
func (_SEVAgentAttestation *SEVAgentAttestationFilterer) WatchOwnershipHandoverRequested(opts *bind.WatchOpts, sink chan<- *SEVAgentAttestationOwnershipHandoverRequested, pendingOwner []common.Address) (event.Subscription, error) {

	var pendingOwnerRule []interface{}
	for _, pendingOwnerItem := range pendingOwner {
		pendingOwnerRule = append(pendingOwnerRule, pendingOwnerItem)
	}

	logs, sub, err := _SEVAgentAttestation.contract.WatchLogs(opts, "OwnershipHandoverRequested", pendingOwnerRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(SEVAgentAttestationOwnershipHandoverRequested)
				if err := _SEVAgentAttestation.contract.UnpackLog(event, "OwnershipHandoverRequested", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseOwnershipHandoverRequested is a log parse operation binding the contract event 0xdbf36a107da19e49527a7176a1babf963b4b0ff8cde35ee35d6cd8f1f9ac7e1d.
//
// Solidity: event OwnershipHandoverRequested(address indexed pendingOwner)
func (_SEVAgentAttestation *SEVAgentAttestationFilterer) ParseOwnershipHandoverRequested(log types.Log) (*SEVAgentAttestationOwnershipHandoverRequested, error) {
	event := new(SEVAgentAttestationOwnershipHandoverRequested)
	if err := _SEVAgentAttestation.contract.UnpackLog(event, "OwnershipHandoverRequested", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// SEVAgentAttestationOwnershipTransferredIterator is returned from FilterOwnershipTransferred and is used to iterate over the raw logs and unpacked data for OwnershipTransferred events raised by the SEVAgentAttestation contract.
type SEVAgentAttestationOwnershipTransferredIterator struct {
	Event *SEVAgentAttestationOwnershipTransferred // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *SEVAgentAttestationOwnershipTransferredIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(SEVAgentAttestationOwnershipTransferred)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(SEVAgentAttestationOwnershipTransferred)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *SEVAgentAttestationOwnershipTransferredIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *SEVAgentAttestationOwnershipTransferredIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// SEVAgentAttestationOwnershipTransferred represents a OwnershipTransferred event raised by the SEVAgentAttestation contract.
type SEVAgentAttestationOwnershipTransferred struct {
	OldOwner common.Address
	NewOwner common.Address
	Raw      types.Log // Blockchain specific contextual infos
}

// FilterOwnershipTransferred is a free log retrieval operation binding the contract event 0x8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e0.
//
// Solidity: event OwnershipTransferred(address indexed oldOwner, address indexed newOwner)
func (_SEVAgentAttestation *SEVAgentAttestationFilterer) FilterOwnershipTransferred(opts *bind.FilterOpts, oldOwner []common.Address, newOwner []common.Address) (*SEVAgentAttestationOwnershipTransferredIterator, error) {

	var oldOwnerRule []interface{}
	for _, oldOwnerItem := range oldOwner {
		oldOwnerRule = append(oldOwnerRule, oldOwnerItem)
	}
	var newOwnerRule []interface{}
	for _, newOwnerItem := range newOwner {
		newOwnerRule = append(newOwnerRule, newOwnerItem)
	}

	logs, sub, err := _SEVAgentAttestation.contract.FilterLogs(opts, "OwnershipTransferred", oldOwnerRule, newOwnerRule)
	if err != nil {
		return nil, err
	}
	return &SEVAgentAttestationOwnershipTransferredIterator{contract: _SEVAgentAttestation.contract, event: "OwnershipTransferred", logs: logs, sub: sub}, nil
}

// WatchOwnershipTransferred is a free log subscription operation binding the contract event 0x8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e0.
//
// Solidity: event OwnershipTransferred(address indexed oldOwner, address indexed newOwner)
func (_SEVAgentAttestation *SEVAgentAttestationFilterer) WatchOwnershipTransferred(opts *bind.WatchOpts, sink chan<- *SEVAgentAttestationOwnershipTransferred, oldOwner []common.Address, newOwner []common.Address) (event.Subscription, error) {

	var oldOwnerRule []interface{}
	for _, oldOwnerItem := range oldOwner {
		oldOwnerRule = append(oldOwnerRule, oldOwnerItem)
	}
	var newOwnerRule []interface{}
	for _, newOwnerItem := range newOwner {
		newOwnerRule = append(newOwnerRule, newOwnerItem)
	}

	logs, sub, err := _SEVAgentAttestation.contract.WatchLogs(opts, "OwnershipTransferred", oldOwnerRule, newOwnerRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(SEVAgentAttestationOwnershipTransferred)
				if err := _SEVAgentAttestation.contract.UnpackLog(event, "OwnershipTransferred", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseOwnershipTransferred is a log parse operation binding the contract event 0x8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e0.
//
// Solidity: event OwnershipTransferred(address indexed oldOwner, address indexed newOwner)
func (_SEVAgentAttestation *SEVAgentAttestationFilterer) ParseOwnershipTransferred(log types.Log) (*SEVAgentAttestationOwnershipTransferred, error) {
	event := new(SEVAgentAttestationOwnershipTransferred)
	if err := _SEVAgentAttestation.contract.UnpackLog(event, "OwnershipTransferred", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// SEVAgentAttestationZkCoProcessorUpdatedIterator is returned from FilterZkCoProcessorUpdated and is used to iterate over the raw logs and unpacked data for ZkCoProcessorUpdated events raised by the SEVAgentAttestation contract.
type SEVAgentAttestationZkCoProcessorUpdatedIterator struct {
	Event *SEVAgentAttestationZkCoProcessorUpdated // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *SEVAgentAttestationZkCoProcessorUpdatedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(SEVAgentAttestationZkCoProcessorUpdated)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(SEVAgentAttestationZkCoProcessorUpdated)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *SEVAgentAttestationZkCoProcessorUpdatedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *SEVAgentAttestationZkCoProcessorUpdatedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// SEVAgentAttestationZkCoProcessorUpdated represents a ZkCoProcessorUpdated event raised by the SEVAgentAttestation contract.
type SEVAgentAttestationZkCoProcessorUpdated struct {
	ZkCoProcessor     uint8
	ProgramIdentifier [32]byte
	ZkVerifier        common.Address
	Raw               types.Log // Blockchain specific contextual infos
}

// FilterZkCoProcessorUpdated is a free log retrieval operation binding the contract event 0xb35538ad1e92ffa864ae8dfa1b6c312bcdb6164cf56a52ad554729a0e6c2d68a.
//
// Solidity: event ZkCoProcessorUpdated(uint8 indexed zkCoProcessor, bytes32 programIdentifier, address zkVerifier)
func (_SEVAgentAttestation *SEVAgentAttestationFilterer) FilterZkCoProcessorUpdated(opts *bind.FilterOpts, zkCoProcessor []uint8) (*SEVAgentAttestationZkCoProcessorUpdatedIterator, error) {

	var zkCoProcessorRule []interface{}
	for _, zkCoProcessorItem := range zkCoProcessor {
		zkCoProcessorRule = append(zkCoProcessorRule, zkCoProcessorItem)
	}

	logs, sub, err := _SEVAgentAttestation.contract.FilterLogs(opts, "ZkCoProcessorUpdated", zkCoProcessorRule)
	if err != nil {
		return nil, err
	}
	return &SEVAgentAttestationZkCoProcessorUpdatedIterator{contract: _SEVAgentAttestation.contract, event: "ZkCoProcessorUpdated", logs: logs, sub: sub}, nil
}

// WatchZkCoProcessorUpdated is a free log subscription operation binding the contract event 0xb35538ad1e92ffa864ae8dfa1b6c312bcdb6164cf56a52ad554729a0e6c2d68a.
//
// Solidity: event ZkCoProcessorUpdated(uint8 indexed zkCoProcessor, bytes32 programIdentifier, address zkVerifier)
func (_SEVAgentAttestation *SEVAgentAttestationFilterer) WatchZkCoProcessorUpdated(opts *bind.WatchOpts, sink chan<- *SEVAgentAttestationZkCoProcessorUpdated, zkCoProcessor []uint8) (event.Subscription, error) {

	var zkCoProcessorRule []interface{}
	for _, zkCoProcessorItem := range zkCoProcessor {
		zkCoProcessorRule = append(zkCoProcessorRule, zkCoProcessorItem)
	}

	logs, sub, err := _SEVAgentAttestation.contract.WatchLogs(opts, "ZkCoProcessorUpdated", zkCoProcessorRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(SEVAgentAttestationZkCoProcessorUpdated)
				if err := _SEVAgentAttestation.contract.UnpackLog(event, "ZkCoProcessorUpdated", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseZkCoProcessorUpdated is a log parse operation binding the contract event 0xb35538ad1e92ffa864ae8dfa1b6c312bcdb6164cf56a52ad554729a0e6c2d68a.
//
// Solidity: event ZkCoProcessorUpdated(uint8 indexed zkCoProcessor, bytes32 programIdentifier, address zkVerifier)
func (_SEVAgentAttestation *SEVAgentAttestationFilterer) ParseZkCoProcessorUpdated(log types.Log) (*SEVAgentAttestationZkCoProcessorUpdated, error) {
	event := new(SEVAgentAttestationZkCoProcessorUpdated)
	if err := _SEVAgentAttestation.contract.UnpackLog(event, "ZkCoProcessorUpdated", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// SEVAgentAttestationZkProgramIdentifierRemovedIterator is returned from FilterZkProgramIdentifierRemoved and is used to iterate over the raw logs and unpacked data for ZkProgramIdentifierRemoved events raised by the SEVAgentAttestation contract.
type SEVAgentAttestationZkProgramIdentifierRemovedIterator struct {
	Event *SEVAgentAttestationZkProgramIdentifierRemoved // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *SEVAgentAttestationZkProgramIdentifierRemovedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(SEVAgentAttestationZkProgramIdentifierRemoved)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(SEVAgentAttestationZkProgramIdentifierRemoved)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *SEVAgentAttestationZkProgramIdentifierRemovedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *SEVAgentAttestationZkProgramIdentifierRemovedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// SEVAgentAttestationZkProgramIdentifierRemoved represents a ZkProgramIdentifierRemoved event raised by the SEVAgentAttestation contract.
type SEVAgentAttestationZkProgramIdentifierRemoved struct {
	ZkCoProcessor     uint8
	ProgramIdentifier [32]byte
	Raw               types.Log // Blockchain specific contextual infos
}

// FilterZkProgramIdentifierRemoved is a free log retrieval operation binding the contract event 0x6c464962a7522a506d44bd8554c02a8d684692e0679175a7d153ac0b80eff4b5.
//
// Solidity: event ZkProgramIdentifierRemoved(uint8 indexed zkCoProcessor, bytes32 programIdentifier)
func (_SEVAgentAttestation *SEVAgentAttestationFilterer) FilterZkProgramIdentifierRemoved(opts *bind.FilterOpts, zkCoProcessor []uint8) (*SEVAgentAttestationZkProgramIdentifierRemovedIterator, error) {

	var zkCoProcessorRule []interface{}
	for _, zkCoProcessorItem := range zkCoProcessor {
		zkCoProcessorRule = append(zkCoProcessorRule, zkCoProcessorItem)
	}

	logs, sub, err := _SEVAgentAttestation.contract.FilterLogs(opts, "ZkProgramIdentifierRemoved", zkCoProcessorRule)
	if err != nil {
		return nil, err
	}
	return &SEVAgentAttestationZkProgramIdentifierRemovedIterator{contract: _SEVAgentAttestation.contract, event: "ZkProgramIdentifierRemoved", logs: logs, sub: sub}, nil
}

// WatchZkProgramIdentifierRemoved is a free log subscription operation binding the contract event 0x6c464962a7522a506d44bd8554c02a8d684692e0679175a7d153ac0b80eff4b5.
//
// Solidity: event ZkProgramIdentifierRemoved(uint8 indexed zkCoProcessor, bytes32 programIdentifier)
func (_SEVAgentAttestation *SEVAgentAttestationFilterer) WatchZkProgramIdentifierRemoved(opts *bind.WatchOpts, sink chan<- *SEVAgentAttestationZkProgramIdentifierRemoved, zkCoProcessor []uint8) (event.Subscription, error) {

	var zkCoProcessorRule []interface{}
	for _, zkCoProcessorItem := range zkCoProcessor {
		zkCoProcessorRule = append(zkCoProcessorRule, zkCoProcessorItem)
	}

	logs, sub, err := _SEVAgentAttestation.contract.WatchLogs(opts, "ZkProgramIdentifierRemoved", zkCoProcessorRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(SEVAgentAttestationZkProgramIdentifierRemoved)
				if err := _SEVAgentAttestation.contract.UnpackLog(event, "ZkProgramIdentifierRemoved", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseZkProgramIdentifierRemoved is a log parse operation binding the contract event 0x6c464962a7522a506d44bd8554c02a8d684692e0679175a7d153ac0b80eff4b5.
//
// Solidity: event ZkProgramIdentifierRemoved(uint8 indexed zkCoProcessor, bytes32 programIdentifier)
func (_SEVAgentAttestation *SEVAgentAttestationFilterer) ParseZkProgramIdentifierRemoved(log types.Log) (*SEVAgentAttestationZkProgramIdentifierRemoved, error) {
	event := new(SEVAgentAttestationZkProgramIdentifierRemoved)
	if err := _SEVAgentAttestation.contract.UnpackLog(event, "ZkProgramIdentifierRemoved", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// SEVAgentAttestationZkRouteAddedIterator is returned from FilterZkRouteAdded and is used to iterate over the raw logs and unpacked data for ZkRouteAdded events raised by the SEVAgentAttestation contract.
type SEVAgentAttestationZkRouteAddedIterator struct {
	Event *SEVAgentAttestationZkRouteAdded // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *SEVAgentAttestationZkRouteAddedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(SEVAgentAttestationZkRouteAdded)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(SEVAgentAttestationZkRouteAdded)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *SEVAgentAttestationZkRouteAddedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *SEVAgentAttestationZkRouteAddedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// SEVAgentAttestationZkRouteAdded represents a ZkRouteAdded event raised by the SEVAgentAttestation contract.
type SEVAgentAttestationZkRouteAdded struct {
	ZkCoProcessor uint8
	Selector      [4]byte
	ZkVerifier    common.Address
	Raw           types.Log // Blockchain specific contextual infos
}

// FilterZkRouteAdded is a free log retrieval operation binding the contract event 0x760c87aaca384c3dc82d5bcce05884a75cf787ef7f7cacaef26a6822b2831dd4.
//
// Solidity: event ZkRouteAdded(uint8 indexed zkCoProcessor, bytes4 selector, address zkVerifier)
func (_SEVAgentAttestation *SEVAgentAttestationFilterer) FilterZkRouteAdded(opts *bind.FilterOpts, zkCoProcessor []uint8) (*SEVAgentAttestationZkRouteAddedIterator, error) {

	var zkCoProcessorRule []interface{}
	for _, zkCoProcessorItem := range zkCoProcessor {
		zkCoProcessorRule = append(zkCoProcessorRule, zkCoProcessorItem)
	}

	logs, sub, err := _SEVAgentAttestation.contract.FilterLogs(opts, "ZkRouteAdded", zkCoProcessorRule)
	if err != nil {
		return nil, err
	}
	return &SEVAgentAttestationZkRouteAddedIterator{contract: _SEVAgentAttestation.contract, event: "ZkRouteAdded", logs: logs, sub: sub}, nil
}

// WatchZkRouteAdded is a free log subscription operation binding the contract event 0x760c87aaca384c3dc82d5bcce05884a75cf787ef7f7cacaef26a6822b2831dd4.
//
// Solidity: event ZkRouteAdded(uint8 indexed zkCoProcessor, bytes4 selector, address zkVerifier)
func (_SEVAgentAttestation *SEVAgentAttestationFilterer) WatchZkRouteAdded(opts *bind.WatchOpts, sink chan<- *SEVAgentAttestationZkRouteAdded, zkCoProcessor []uint8) (event.Subscription, error) {

	var zkCoProcessorRule []interface{}
	for _, zkCoProcessorItem := range zkCoProcessor {
		zkCoProcessorRule = append(zkCoProcessorRule, zkCoProcessorItem)
	}

	logs, sub, err := _SEVAgentAttestation.contract.WatchLogs(opts, "ZkRouteAdded", zkCoProcessorRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(SEVAgentAttestationZkRouteAdded)
				if err := _SEVAgentAttestation.contract.UnpackLog(event, "ZkRouteAdded", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseZkRouteAdded is a log parse operation binding the contract event 0x760c87aaca384c3dc82d5bcce05884a75cf787ef7f7cacaef26a6822b2831dd4.
//
// Solidity: event ZkRouteAdded(uint8 indexed zkCoProcessor, bytes4 selector, address zkVerifier)
func (_SEVAgentAttestation *SEVAgentAttestationFilterer) ParseZkRouteAdded(log types.Log) (*SEVAgentAttestationZkRouteAdded, error) {
	event := new(SEVAgentAttestationZkRouteAdded)
	if err := _SEVAgentAttestation.contract.UnpackLog(event, "ZkRouteAdded", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// SEVAgentAttestationZkRouteFrozenIterator is returned from FilterZkRouteFrozen and is used to iterate over the raw logs and unpacked data for ZkRouteFrozen events raised by the SEVAgentAttestation contract.
type SEVAgentAttestationZkRouteFrozenIterator struct {
	Event *SEVAgentAttestationZkRouteFrozen // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *SEVAgentAttestationZkRouteFrozenIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(SEVAgentAttestationZkRouteFrozen)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(SEVAgentAttestationZkRouteFrozen)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *SEVAgentAttestationZkRouteFrozenIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *SEVAgentAttestationZkRouteFrozenIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// SEVAgentAttestationZkRouteFrozen represents a ZkRouteFrozen event raised by the SEVAgentAttestation contract.
type SEVAgentAttestationZkRouteFrozen struct {
	ZkCoProcessor uint8
	Selector      [4]byte
	Raw           types.Log // Blockchain specific contextual infos
}

// FilterZkRouteFrozen is a free log retrieval operation binding the contract event 0x029a2a6861fdad4bb62d2049299c3ddfe06f31578da3a6f11873a41c3058308c.
//
// Solidity: event ZkRouteFrozen(uint8 indexed zkCoProcessor, bytes4 selector)
func (_SEVAgentAttestation *SEVAgentAttestationFilterer) FilterZkRouteFrozen(opts *bind.FilterOpts, zkCoProcessor []uint8) (*SEVAgentAttestationZkRouteFrozenIterator, error) {

	var zkCoProcessorRule []interface{}
	for _, zkCoProcessorItem := range zkCoProcessor {
		zkCoProcessorRule = append(zkCoProcessorRule, zkCoProcessorItem)
	}

	logs, sub, err := _SEVAgentAttestation.contract.FilterLogs(opts, "ZkRouteFrozen", zkCoProcessorRule)
	if err != nil {
		return nil, err
	}
	return &SEVAgentAttestationZkRouteFrozenIterator{contract: _SEVAgentAttestation.contract, event: "ZkRouteFrozen", logs: logs, sub: sub}, nil
}

// WatchZkRouteFrozen is a free log subscription operation binding the contract event 0x029a2a6861fdad4bb62d2049299c3ddfe06f31578da3a6f11873a41c3058308c.
//
// Solidity: event ZkRouteFrozen(uint8 indexed zkCoProcessor, bytes4 selector)
func (_SEVAgentAttestation *SEVAgentAttestationFilterer) WatchZkRouteFrozen(opts *bind.WatchOpts, sink chan<- *SEVAgentAttestationZkRouteFrozen, zkCoProcessor []uint8) (event.Subscription, error) {

	var zkCoProcessorRule []interface{}
	for _, zkCoProcessorItem := range zkCoProcessor {
		zkCoProcessorRule = append(zkCoProcessorRule, zkCoProcessorItem)
	}

	logs, sub, err := _SEVAgentAttestation.contract.WatchLogs(opts, "ZkRouteFrozen", zkCoProcessorRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(SEVAgentAttestationZkRouteFrozen)
				if err := _SEVAgentAttestation.contract.UnpackLog(event, "ZkRouteFrozen", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseZkRouteFrozen is a log parse operation binding the contract event 0x029a2a6861fdad4bb62d2049299c3ddfe06f31578da3a6f11873a41c3058308c.
//
// Solidity: event ZkRouteFrozen(uint8 indexed zkCoProcessor, bytes4 selector)
func (_SEVAgentAttestation *SEVAgentAttestationFilterer) ParseZkRouteFrozen(log types.Log) (*SEVAgentAttestationZkRouteFrozen, error) {
	event := new(SEVAgentAttestationZkRouteFrozen)
	if err := _SEVAgentAttestation.contract.UnpackLog(event, "ZkRouteFrozen", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}
