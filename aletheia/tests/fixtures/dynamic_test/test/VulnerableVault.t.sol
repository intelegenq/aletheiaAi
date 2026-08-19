// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {Test, console2} from "forge-std/Test.sol";
import {VulnerableVault} from "../contracts/VulnerableVault.sol";

contract VulnerableVaultTest is Test {
    VulnerableVault vault;
    address originalOwner;

    function setUp() public {
        vault = new VulnerableVault();
        originalOwner = address(this);
        vm.deal(address(this), 100 ether);
        vault.deposit{value: 10 ether}();
    }

    // FAILING: attacker can call withdrawFrom and steal user funds
    function test_withdrawFrom_onlySelf() public {
        address attacker = makeAddr("attacker");
        vm.deal(attacker, 1 ether);
        vm.prank(attacker);
        vault.withdrawFrom(address(this), 10 ether);  // should revert, but doesn't

        // attacker stole the funds — this assertion fails
        assertEq(vault.balances(address(this)), 10 ether, "victim balance should be intact");
    }

    // FAILING: attacker can call setOwner and take ownership
    function test_onlyOwnerCanSetOwner() public {
        address attacker = makeAddr("attacker");
        vm.prank(attacker);
        vault.setOwner(attacker);  // should revert, but doesn't

        // ownership was stolen — this assertion fails
        assertEq(vault.owner(), originalOwner, "owner should remain original");
    }
}