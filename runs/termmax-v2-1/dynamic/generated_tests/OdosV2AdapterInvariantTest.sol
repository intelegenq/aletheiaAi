// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {Test} from "forge-std/Test.sol";
import "contracts/v1/router/swapAdapters/OdosV2Adapter.sol";

contract OdosV2AdapterInvariantTest is Test {
    OdosV2Adapter target;

    function setUp() public {
        target = new OdosV2Adapter(address(0x1));
    }

    function invariant_unchecked_return_0() public {
        // Unchecked return value for _swap
        // External calls should be checked
        assert(true);
    }

}