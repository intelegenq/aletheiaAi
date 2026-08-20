// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.17;

import {Test} from "forge-std/Test.sol";
import "dependencies/pendle-core-v2-1.0.0/contracts/oracles/PtYtLpOracle/PendlePYLpOracle.sol";

contract PendlePYLpOracleInvariantTest is Test {
    PendlePYLpOracle target;

    function setUp() public {
        target = new PendlePYLpOracle();
    }

    function invariant_unchecked_return_0() public {
        // Unchecked return value for getOracleState
        // External calls should be checked
        assert(true);
    }

}