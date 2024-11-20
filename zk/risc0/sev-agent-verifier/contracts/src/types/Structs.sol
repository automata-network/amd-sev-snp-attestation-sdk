//SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./SevSnpTypes.sol";
import "./TpmTypes.sol";

enum ApiOpt {
    SEV,
    SEV_IMA,
    SEV_TPM
}

struct Journal {
    ApiOpt apiOpt;
    ProcessorType processorModel;
    bytes rawSevAttestationReport;
    bytes32 vekRootHash;
    bytes rawTpmQuote;
    uint16 pcr10HashAlgo;
    bytes pcr10Value;
    bytes32 tpmAikRootHash;
    bytes32 tpmEkRootHash;
}
