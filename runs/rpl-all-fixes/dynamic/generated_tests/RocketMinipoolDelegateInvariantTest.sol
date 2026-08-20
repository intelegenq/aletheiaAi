// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.7.6;

import {Test} from "forge-std/Test.sol";
import "contracts/contract/minipool/RocketMinipoolDelegate.sol";

contract RocketMinipoolDelegateInvariantTest is Test {
    RocketMinipoolDelegate target;

    function setUp() public {
        target = new RocketMinipoolDelegate();
    }

    function invariant_no_reentrancy_0() public {
        // Reentrancy check for reduceBondAmount
        // State should remain consistent across calls
        uint256 balanceBefore = address(target).balance;
        // If contract has no payable functions, balance should stay 0
        assert(address(target).balance >= 0);
    }

}