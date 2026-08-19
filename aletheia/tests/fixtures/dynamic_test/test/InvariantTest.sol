// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {Test} from "forge-std/Test.sol";
import {VulnerableVault} from "../contracts/VulnerableVault.sol";

contract InvariantTest is Test {
    VulnerableVault vault;

    function setUp() public {
        vault = new VulnerableVault();
        vm.deal(address(this), 100 ether);
        vault.deposit{value: 10 ether}();
    }

    // INVARIANT: owner must never change unless it was the owner who called
    // Fails because setOwner has no access control.
    function invariant_owner_is_original() external {
        assertEq(vault.owner(), address(this), "owner should never change");
    }

    // INVARIANT: total deposited balance must equal vault balance
    // Fails because withdrawFrom lets anyone drain.
    function invariant_vault_balance_nonzero() external {
        assertGt(address(vault).balance, 0, "vault must never be drained");
    }
}