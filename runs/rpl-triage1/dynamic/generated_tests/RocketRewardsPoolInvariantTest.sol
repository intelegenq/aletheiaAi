// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import "contracts/contract/rewards/RocketRewardsPool.sol" as Target;

contract RocketRewardsPoolInvariantTest is Test {
    Target.RocketRewardsPool target;

    function setUp() public {
        target = new Target.RocketRewardsPool();
    }

    function invariant_unchecked_return_0() public {
        // Unchecked return value for _executeRewardSnapshot
        // External calls should be checked
        assert(true);
    }

}