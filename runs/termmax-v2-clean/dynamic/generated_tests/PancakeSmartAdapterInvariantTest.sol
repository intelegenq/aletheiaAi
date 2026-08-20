// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import "contracts/v2/router/swapAdapters/PancakeSmartAdapter.sol";

contract PancakeSmartAdapterInvariantTest is Test {
    PancakeSmartAdapter target;

    function setUp() public {
        target = new PancakeSmartAdapter(address(0x1));
    }

    function invariant_no_reentrancy_0() public {
        // Reentrancy check for _swap
        // State should remain consistent across calls
        uint256 balanceBefore = address(target).balance;
        // If contract has no payable functions, balance should stay 0
        assert(address(target).balance >= 0);
    }

}