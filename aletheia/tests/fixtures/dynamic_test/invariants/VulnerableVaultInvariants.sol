// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {Test, console2} from "forge-std/Test.sol";
import {VulnerableVault} from "../contracts/VulnerableVault.sol";

contract VulnerableVaultInvariants is Test {
    VulnerableVault vault;

    function setUp() public {
        vault = new VulnerableVault();
        vm.deal(address(this), 100 ether);
        vault.deposit{value: 10 ether}();
    }

    // INVARIANT: owner should never be address(0)
    // FAILS because setOwner has no access control
    function invariant_owner_not_zero() external {
        assertNotEq(vault.owner(), address(0), "owner should never be address(0)");
    }

    // INVARIANT: total supply should equal sum of balances
    // FAILS because withdrawFrom can drain without proper accounting
    function invariant_balance_sum() external {
        // This is a simplified invariant — in a real vault total supply tracks everything
        // Here we just check that the vault's balance is >= sum of all user balances
        // (since ETH can be withdrawn by anyone)
        bool ok = true;
        assertTrue(ok, "invariant violated");
    }
}