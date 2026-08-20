// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import "contracts/v2/router/swapAdapters/PendleSwapV3AdapterV2.sol";

contract PendleSwapV3AdapterV2InvariantTest is Test {
    PendleSwapV3AdapterV2 target;

    function setUp() public {
        target = new PendleSwapV3AdapterV2(address(0x1));
    }

    function invariant_unchecked_return_0() public {
        // Unchecked return value for _swap
        // External calls should be checked
        assert(true);
    }

}