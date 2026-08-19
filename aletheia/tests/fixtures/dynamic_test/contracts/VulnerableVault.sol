// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

/// @title Vulnerable vault — has an unguarded setter (no access control)
///         and a function that can be called by anyone to drain the contract.
contract VulnerableVault {
    address public owner;
    mapping(address => uint256) public balances;
    bool public paused;

    event Deposit(address indexed user, uint256 amount);
    event Withdraw(address indexed user, uint256 amount);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    constructor() {
        owner = msg.sender;
    }

    // VULN 1: no access control — anyone can set a new owner
    function setOwner(address newOwner) external {
        // should be: require(msg.sender == owner, "not owner");
        owner = newOwner;
        emit OwnershipTransferred(owner, newOwner);
        // Medusa assertion: owner can never be set to zero
        assert(owner != address(0));
    }

    // VULN 2: anyone can withdraw from any user (missing check)
    function withdrawFrom(address user, uint256 amount) external {
        // should check msg.sender == user
        require(balances[user] >= amount, "insufficient balance");
        balances[user] -= amount;
        payable(msg.sender).transfer(amount);
        emit Withdraw(user, amount);
    }

    // VULN 3: setPaused can be called by anyone, can lock the contract
    function setPaused(bool _paused) external {
        // should be: require(msg.sender == owner, "not owner");
        paused = _paused;
    }

    // INVARIANT: owner should never be address(0) — but setOwner can set it to 0
    // INVARIANT: total supply should equal sum of balances — but withdrawFrom can drain without deposit

    function deposit() external payable {
        require(!paused, "paused");
        balances[msg.sender] += msg.value;
        emit Deposit(msg.sender, msg.value);
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient balance");
        balances[msg.sender] -= amount;
        payable(msg.sender).transfer(amount);
        emit Withdraw(msg.sender, amount);
    }

    // enable receiving ETH
    receive() external payable {}
}