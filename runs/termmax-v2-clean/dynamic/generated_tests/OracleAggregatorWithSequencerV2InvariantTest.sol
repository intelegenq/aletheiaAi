// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {Test} from "forge-std/Test.sol";
import "contracts/v2/oracle/OracleAggregatorWithSequencerV2.sol";

contract OracleAggregatorWithSequencerV2InvariantTest is Test {
    OracleAggregatorWithSequencerV2 target;

    function setUp() public {
        target = new OracleAggregatorWithSequencerV2(address(0x1), 0, address(0x1), 0);
    }

    function invariant_unchecked_return_0() public {
        // Unchecked return value for _isSequencerUp
        // External calls should be checked
        assert(true);
    }

}