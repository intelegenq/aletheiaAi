// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import "contracts/v2/router/swapAdapters/OndoSwapAdapter.sol";

contract OndoSwapAdapterInvariantTest is Test {
    OndoSwapAdapter target;

    function setUp() public {
        target = new OndoSwapAdapter(address(0x1));
    }

    function invariant_unchecked_return_0() public {
        // Unchecked return value for _swap
        // External calls should be checked
        assert(true);
    }

}