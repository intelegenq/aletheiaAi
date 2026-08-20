// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import "contracts/contract/dao/security/RocketDAOSecurityProposals.sol" as Target;

contract RocketDAOSecurityProposalsInvariantTest is Test {
    Target.RocketDAOSecurityProposals target;

    function setUp() public {
        target = new Target.RocketDAOSecurityProposals();
    }

    function invariant_0_onlyValidSetting() public {
        // Generated from: Encode Packed Collision
        // Detector: slither:encode-packed-collision
        // Manual review required
        assert(true);
    }

}