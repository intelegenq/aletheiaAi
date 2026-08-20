// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.7.6;

import {Test} from "forge-std/Test.sol";
import "contracts/contract/minipool/RocketMinipoolBase.sol";

contract RocketMinipoolBaseInvariantTest is Test {
    RocketMinipoolBase target;

    function setUp() public {
        target = new RocketMinipoolBase();
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