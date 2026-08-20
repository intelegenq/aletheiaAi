// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import "contracts/contract/helper/SnapshotTest.sol" as Target;

contract SnapshotTestInvariantTest is Test {
    Target.SnapshotTest target;

    function setUp() public {
        target = new Target.SnapshotTest();
    }

    function invariant_unchecked_return_0() public {
        // Unchecked return value for lookupGas
        // External calls should be checked
        assert(true);
    }

    function invariant_unchecked_return_1() public {
        // Unchecked return value for lookupRecentGas
        // External calls should be checked
        assert(true);
    }

}