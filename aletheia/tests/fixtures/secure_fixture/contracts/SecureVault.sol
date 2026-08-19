// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

/// @title Secure vault — SAME shape as VulnerableVault but with real guards.
/// Used as negative control: conviction must NOT verify findings here.
contract SecureVault {
    address public owner;
    bool public paused;
    mapping(address => uint256) public balances;

    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    event Paused(bool paused);
    event Deposit(address indexed user, uint256 amount);
    event Withdraw(address indexed user, uint256 amount);

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    // GUARDED: onlyOwner enforced
    function setOwner(address newOwner) external onlyOwner {
        require(newOwner != address(0), "zero owner");
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }

    // GUARDED: onlyOwner enforced
    function setPaused(bool newPaused) external onlyOwner {
        paused = newPaused;
        emit Paused(newPaused);
    }

    function deposit() external payable {
        require(msg.value > 0, "zero value");
        balances[msg.sender] += msg.value;
        emit Deposit(msg.sender, msg.value);
    }

    // GUARDED: only self
    function withdraw(uint256 amount) external {
        require(amount <= balances[msg.sender], "insufficient");
        balances[msg.sender] -= amount;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
        emit Withdraw(msg.sender, amount);
    }

    // GUARDED: owner only with self-check
    function withdrawFrom(address user, uint256 amount) external onlyOwner {
        require(amount <= balances[user], "insufficient");
        balances[user] -= amount;
        (bool ok, ) = user.call{value: amount}("");
        require(ok, "transfer failed");
        emit Withdraw(user, amount);
    }

    /// @notice internal-only helper; surgery on owner — but ONLY reachable via
    ///         the guarded public path. Looks dangerous if scanned naively.
    function _internalOwnerSurgery(address newOwner) internal {
        owner = newOwner;
    }

    /// @notice public path to _internalOwnerSurgery — but guarded by a check
    ///         that makes the vulnerable arrangement impossible.
    function publicOwnerChange(address newOwner) external onlyOwner {
        _internalOwnerSurgery(newOwner);
    }
}