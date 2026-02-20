// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {Ownable2Step} from "@openzeppelin/contracts/access/Ownable2Step.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";

/// @title SaltaXTreasury
/// @notice On-chain treasury with three policy checks mirroring
///         src/treasury/policy.py TreasuryPolicy.validate_payout().
/// @dev Policy parameters are immutable — deploy a new contract to change them.
///      Basis-point arithmetic: 1 bps = 0.01%, 10000 bps = 100%.
contract SaltaXTreasury is Ownable2Step, ReentrancyGuard, Pausable {
    // ── Immutable Config ─────────────────────────────────────────────────
    /// @notice Minimum fraction of balance that must remain after a payout (bps).
    uint256 public immutable reserveRatioBps;

    /// @notice Maximum fraction of balance available for bounty payouts (bps).
    uint256 public immutable bountyBudgetBps;

    /// @notice Hard cap on any single payout (wei).
    uint256 public immutable maxSinglePayoutWei;

    // ── Custom Errors ────────────────────────────────────────────────────
    error PayoutExceedsMaxSingle(uint256 amount, uint256 max);
    error PayoutViolatesReserve(uint256 remaining, uint256 requiredReserve);
    error PayoutExceedsBountyBudget(uint256 amount, uint256 budget);
    error TransferFailed();
    error ZeroAmount();
    error ZeroAddress();
    error InsufficientBalance(uint256 requested, uint256 available);
    error RenounceOwnershipDisabled();
    error InvalidReserveRatio(uint256 bps);
    error InvalidBountyBudget(uint256 bps);
    error InvalidMaxPayout();

    // ── Events ───────────────────────────────────────────────────────────
    event PayoutExecuted(address indexed to, uint256 amount);
    event FundsReceived(address indexed from, uint256 amount);

    // ── Constructor ──────────────────────────────────────────────────────
    /// @param initialOwner      Address that controls withdrawals.
    /// @param _reserveRatioBps  Reserve ratio in basis points (e.g. 2000 = 20%).
    /// @param _bountyBudgetBps  Bounty budget in basis points (e.g. 6500 = 65%).
    /// @param _maxSinglePayoutWei Hard cap per payout in wei.
    constructor(
        address initialOwner,
        uint256 _reserveRatioBps,
        uint256 _bountyBudgetBps,
        uint256 _maxSinglePayoutWei
    ) Ownable(initialOwner) {
        if (_reserveRatioBps > 10_000) revert InvalidReserveRatio(_reserveRatioBps);
        if (_bountyBudgetBps > 10_000) revert InvalidBountyBudget(_bountyBudgetBps);
        if (_maxSinglePayoutWei == 0) revert InvalidMaxPayout();

        reserveRatioBps = _reserveRatioBps;
        bountyBudgetBps = _bountyBudgetBps;
        maxSinglePayoutWei = _maxSinglePayoutWei;
    }

    // ── Ownership Override ────────────────────────────────────────────────

    /// @notice Disabled — renouncing ownership would brick the contract.
    function renounceOwnership() public override onlyOwner {
        revert RenounceOwnershipDisabled();
    }

    // ── Pause Controls ───────────────────────────────────────────────────

    /// @notice Pause all payout operations (emergency circuit breaker).
    function pause() external onlyOwner {
        _pause();
    }

    /// @notice Resume payout operations after emergency.
    function unpause() external onlyOwner {
        _unpause();
    }

    // ── Withdraw ─────────────────────────────────────────────────────────

    /// @notice Execute a payout after validating three treasury policies.
    /// @dev Mirrors the Python TreasuryPolicy.validate_payout() checks:
    ///      1. amount <= maxSinglePayoutWei
    ///      2. (balance - amount) >= (balance * reserveRatioBps) / 10000
    ///      3. amount <= (balance * bountyBudgetBps) / 10000
    /// @param to     Recipient address.
    /// @param amount Wei to send.
    function withdraw(address to, uint256 amount) external onlyOwner whenNotPaused nonReentrant {
        if (amount == 0) revert ZeroAmount();
        if (to == address(0)) revert ZeroAddress();

        uint256 balance = address(this).balance;

        if (amount > balance) revert InsufficientBalance(amount, balance);

        // Check 1: max single payout
        if (amount > maxSinglePayoutWei) {
            revert PayoutExceedsMaxSingle(amount, maxSinglePayoutWei);
        }

        // Check 2: reserve ratio — remaining balance must meet reserve
        uint256 requiredReserve = (balance * reserveRatioBps) / 10_000;
        if (balance - amount < requiredReserve) {
            revert PayoutViolatesReserve(balance - amount, requiredReserve);
        }

        // Check 3: bounty budget — payout must fit within bounty allocation
        uint256 budget = (balance * bountyBudgetBps) / 10_000;
        if (amount > budget) {
            revert PayoutExceedsBountyBudget(amount, budget);
        }

        emit PayoutExecuted(to, amount);

        (bool ok, ) = to.call{value: amount}("");
        if (!ok) revert TransferFailed();
    }

    /// @notice Accept direct ETH transfers (treasury funding).
    /// @dev NOT pausable — emergency recapitalization must always work.
    receive() external payable {
        emit FundsReceived(msg.sender, msg.value);
    }
}
