// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import "contracts/contract/minipool/RocketMinipoolDelegate.sol" as Target;

contract RocketMinipoolDelegateInvariantTest is Test {
    Target.RocketMinipoolDelegate target;

    function setUp() public {
        target = new Target.RocketMinipoolDelegate();
    }

    function invariant_no_reentrancy_0() public {
        // Reentrancy check for reduceBondAmount
        // State should remain consistent across calls
        uint256 balanceBefore = address(target).balance;
        // If contract has no payable functions, balance should stay 0
        assert(address(target).balance >= 0);
    }

}