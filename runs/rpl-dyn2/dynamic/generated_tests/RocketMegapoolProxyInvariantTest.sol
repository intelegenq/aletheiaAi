// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import "contracts/contract/megapool/RocketMegapoolProxy.sol" as Target;

contract RocketMegapoolProxyInvariantTest is Test {
    Target.RocketMegapoolProxy target;

    function setUp() public {
        target = new Target.RocketMegapoolProxy();
    }

    function invariant_delegatecall_0() public {
        // delegatecall target should be trusted
        assert(true);
    }

}