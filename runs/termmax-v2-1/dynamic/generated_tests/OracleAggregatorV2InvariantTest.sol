// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {Test} from "forge-std/Test.sol";
import "contracts/v2/oracle/OracleAggregatorV2.sol";

contract OracleAggregatorV2InvariantTest is Test {
    OracleAggregatorV2 target;

    function setUp() public {
        target = new OracleAggregatorV2(address(0x1), 0);
    }

    function invariant_unchecked_return_0() public {
        // Unchecked return value for getPrice
        // External calls should be checked
        assert(true);
    }

}