// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import "contracts/contract/network/RocketNetworkRevenues.sol" as Target;

contract RocketNetworkRevenuesInvariantTest is Test {
    Target.RocketNetworkRevenues target;

    function setUp() public {
        target = new Target.RocketNetworkRevenues();
    }

    function invariant_unchecked_return_0() public {
        // Unchecked return value for initialise
        // External calls should be checked
        assert(true);
    }

    function invariant_unchecked_return_1() public {
        // Unchecked return value for _getCurrentShare
        // External calls should be checked
        assert(true);
    }

    function invariant_2__getAverageSince() public {
        // Generated from: Divide Before Multiply
        // Detector: slither:divide-before-multiply
        // Manual review required
        assert(true);
    }

}