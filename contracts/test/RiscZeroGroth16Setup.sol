// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "risc0/groth16/RiscZeroGroth16Verifier.sol";
import "risc0/groth16/ControlID.sol";

abstract contract RiscZeroGroth16Setup is Test {
    RiscZeroGroth16Verifier internal riscZeroVerifier;

    function setUp() public virtual {
        riscZeroVerifier = new RiscZeroGroth16Verifier(ControlID.CONTROL_ROOT, ControlID.BN254_CONTROL_ID);
    }
}
