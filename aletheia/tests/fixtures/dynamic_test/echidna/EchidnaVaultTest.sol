// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {VulnerableVault} from "../contracts/VulnerableVault.sol";

/// @title Echidna properties for VulnerableVault
/// @notice Properties FAIL because the contract is vulnerable:
///         1. owner can be stolen via setOwner (no access control)
///         2. vault can be drained via withdrawFrom
contract EchidnaVaultTest {
    VulnerableVault vault;

    constructor() payable {
        vault = new VulnerableVault();
    }

    // ---- echidna-callable wrappers (these are fuzzed) ----

    function deposit() external payable {
        vault.deposit{value: msg.value}();
    }

    // attacker can call this freely — should revert but won't
    function attack_setOwner(address newOwner) external {
        vault.setOwner(newOwner);
    }

    // attacker can call this freely — should revert but won't
    function attack_withdrawFrom(address victim, uint256 amount) external {
        vault.withdrawFrom(victim, amount);
    }

    // PROPERTY 1: owner must never change — FAILS via attack_setOwner
    function echidna_owner_unchanged() public view returns (bool) {
        return address(vault.owner()) == address(this);
    }

    // PROPERTY 2: once echidna deposits, vault must never be fully drained
    // by a third party. Track "has ever deposited" via a flag.
    function echidna_vault_not_empty() public view returns (bool) {
        // If no deposit ever happened, vault may legitimately be 0 — pass.
        // Once a deposit happened, vault balance must stay > 0.
        if (hasDeposited) {
            return address(vault).balance > 0;
        }
        return true;
    }

    bool public hasDeposited;

    function deposit_tracked() external payable {
        vault.deposit{value: msg.value}();
        hasDeposited = true;
    }
}