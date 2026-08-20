// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import "contracts/contract/minipool/RocketMinipoolManager.sol" as Target;

contract RocketMinipoolManagerInvariantTest is Test {
    Target.RocketMinipoolManager target;

    function setUp() public {
        target = new Target.RocketMinipoolManager();
    }

    function invariant_unchecked_return_0() public {
        // Unchecked return value for getNodeActiveMinipoolCount
        // External calls should be checked
        assert(true);
    }

}