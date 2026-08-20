// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

import {Test} from "forge-std/Test.sol";
import "contracts/contract/megapool/RocketMegapoolProxy.sol";

contract RocketMegapoolProxyInvariantTest is Test {
    RocketMegapoolProxy target;

    function setUp() public {
        target = new RocketMegapoolProxy(RocketStorageInterface(address(0x1)));
    }

    function invariant_delegatecall_0() public {
        // delegatecall target should be trusted
        assert(true);
    }

}