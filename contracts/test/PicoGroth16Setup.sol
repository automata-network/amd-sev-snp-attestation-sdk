// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import {PicoVerifier} from "../src/pico/PicoVerifier.sol";

abstract contract PicoGroth16Setup {
    PicoVerifier internal picoVerifier;

    function setupPico() internal returns (address) {
        picoVerifier = new PicoVerifier();
        return address(picoVerifier);
    }
}
