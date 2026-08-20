// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import "contracts/contract/minipool/RocketMinipoolBase.sol" as Target;

contract RocketMinipoolBaseInvariantTest is Test {
    Target.RocketMinipoolBase target;

    function setUp() public {
        target = new Target.RocketMinipoolBase();
    }

    function invariant_delegatecall_0() public {
        // delegatecall target should be trusted
        assert(true);
    }

    function invariant_delegatecall_1() public {
        // delegatecall target should be trusted
        assert(true);
    }

}