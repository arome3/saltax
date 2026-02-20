// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {Ownable2Step} from "@openzeppelin/contracts/access/Ownable2Step.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";

/// @title SaltaXStaking
/// @notice Trustless staking contract for SaltaX contributor PRs.
/// @dev Field order in the Stake struct is dictated by the Python ABI in
///      src/staking/contract.py — the auto-generated getter must return
///      (address, uint256, bytes32, bool, uint256).
contract SaltaXStaking is Ownable2Step, ReentrancyGuard, Pausable {
    // ── Struct ───────────────────────────────────────────────────────────
    // Field order MUST match Python ABI: staker, amount, prId, resolved, timestamp
    struct Stake {
        address contributor;
        uint256 amount;
        bytes32 prId;
        bool resolved;
        uint256 depositedAt;
    }

    // ── State ────────────────────────────────────────────────────────────
    mapping(bytes32 => Stake) public stakes;
    uint256 public totalSlashedFunds;

    // ── Custom Errors ────────────────────────────────────────────────────
    error StakeMustBePositive();
    error StakeAlreadyExists(bytes32 stakeId);
    error StakeNotFound(bytes32 stakeId);
    error StakeAlreadyResolved(bytes32 stakeId);
    error InvalidSlashPercent(uint256 percent);
    error TransferFailed();
    error InsufficientSlashedFunds(uint256 requested, uint256 available);
    error RenounceOwnershipDisabled();

    // ── Events ───────────────────────────────────────────────────────────
    event StakeDeposited(
        bytes32 indexed stakeId,
        address indexed contributor,
        uint256 amount,
        bytes32 prId
    );
    event StakeReleased(
        bytes32 indexed stakeId,
        address indexed contributor,
        uint256 returnAmount,
        uint256 bonus
    );
    event PartialRelease(
        bytes32 indexed stakeId,
        address indexed contributor,
        uint256 requested,
        uint256 actual
    );
    event StakeSlashed(
        bytes32 indexed stakeId,
        address indexed contributor,
        uint256 returnAmount,
        uint256 slashAmount
    );
    event StakeRefunded(
        bytes32 indexed stakeId,
        address indexed contributor,
        uint256 amount
    );
    event SlashedWithdrawn(address indexed to, uint256 amount);

    // ── Constructor ──────────────────────────────────────────────────────
    constructor(address initialOwner) Ownable(initialOwner) {}

    // ── Ownership Override ────────────────────────────────────────────────

    /// @notice Disabled — renouncing ownership would brick the contract.
    function renounceOwnership() public override onlyOwner {
        revert RenounceOwnershipDisabled();
    }

    // ── Pause Controls ───────────────────────────────────────────────────

    /// @notice Pause all stake operations (emergency circuit breaker).
    function pause() external onlyOwner {
        _pause();
    }

    /// @notice Resume stake operations after emergency.
    function unpause() external onlyOwner {
        _unpause();
    }

    // ── Public Functions ─────────────────────────────────────────────────

    /// @notice Deposit ETH as a stake for a PR contribution.
    /// @param stakeId Unique identifier for this stake.
    /// @param prId    Identifier for the associated pull request.
    function depositStake(bytes32 stakeId, bytes32 prId) external payable whenNotPaused {
        if (msg.value == 0) revert StakeMustBePositive();
        if (stakes[stakeId].amount != 0) revert StakeAlreadyExists(stakeId);

        stakes[stakeId] = Stake({
            contributor: msg.sender,
            amount: msg.value,
            prId: prId,
            resolved: false,
            depositedAt: block.timestamp
        });

        emit StakeDeposited(stakeId, msg.sender, msg.value, prId);
    }

    /// @notice Release a stake plus an optional bonus to the contributor.
    /// @dev If the contract balance is insufficient for stake + bonus, a
    ///      partial release is performed and PartialRelease is emitted instead.
    /// @param stakeId    The stake to release.
    /// @param bonusAmount Additional ETH bonus from the pool.
    function releaseStake(bytes32 stakeId, uint256 bonusAmount) external onlyOwner whenNotPaused nonReentrant {
        Stake storage s = stakes[stakeId];
        if (s.amount == 0) revert StakeNotFound(stakeId);
        if (s.resolved) revert StakeAlreadyResolved(stakeId);

        s.resolved = true;

        uint256 totalReturn = s.amount + bonusAmount;
        address contributor = s.contributor;

        if (address(this).balance < totalReturn) {
            // Partial release — send whatever is available
            uint256 actual = address(this).balance;
            emit PartialRelease(stakeId, contributor, totalReturn, actual);
            totalReturn = actual;
        } else {
            emit StakeReleased(stakeId, contributor, s.amount, bonusAmount);
        }

        if (totalReturn > 0) {
            (bool ok, ) = contributor.call{value: totalReturn}("");
            if (!ok) revert TransferFailed();
        }
    }

    /// @notice Slash a percentage of a contributor's stake.
    /// @dev slashPercent is 1–100 (not basis points). 100 means full slash.
    ///      The slashed portion accumulates in totalSlashedFunds and can be
    ///      withdrawn by the owner.
    /// @param stakeId      The stake to slash.
    /// @param slashPercent  Percentage to slash (1–100).
    function slashStake(bytes32 stakeId, uint256 slashPercent) external onlyOwner whenNotPaused nonReentrant {
        if (slashPercent == 0 || slashPercent > 100) revert InvalidSlashPercent(slashPercent);

        Stake storage s = stakes[stakeId];
        if (s.amount == 0) revert StakeNotFound(stakeId);
        if (s.resolved) revert StakeAlreadyResolved(stakeId);

        s.resolved = true;

        uint256 slashAmount = (s.amount * slashPercent) / 100;
        uint256 returnAmount = s.amount - slashAmount;
        address contributor = s.contributor;

        totalSlashedFunds += slashAmount;

        emit StakeSlashed(stakeId, contributor, returnAmount, slashAmount);

        if (returnAmount > 0) {
            (bool ok, ) = contributor.call{value: returnAmount}("");
            if (!ok) revert TransferFailed();
        }
    }

    /// @notice Full refund of a stake (e.g. rejected PR, no fault).
    /// @param stakeId The stake to refund.
    function refundStake(bytes32 stakeId) external onlyOwner whenNotPaused nonReentrant {
        Stake storage s = stakes[stakeId];
        if (s.amount == 0) revert StakeNotFound(stakeId);
        if (s.resolved) revert StakeAlreadyResolved(stakeId);

        s.resolved = true;

        uint256 refundAmount = s.amount;
        address contributor = s.contributor;

        emit StakeRefunded(stakeId, contributor, refundAmount);

        (bool ok, ) = contributor.call{value: refundAmount}("");
        if (!ok) revert TransferFailed();
    }

    /// @notice Withdraw accumulated slashed funds to the owner.
    /// @dev Guarded by totalSlashedFunds to prevent draining the bonus pool.
    /// @param amount Wei to withdraw (must be <= totalSlashedFunds).
    function withdrawSlashed(uint256 amount) external onlyOwner whenNotPaused nonReentrant {
        if (amount > totalSlashedFunds) {
            revert InsufficientSlashedFunds(amount, totalSlashedFunds);
        }

        totalSlashedFunds -= amount;

        emit SlashedWithdrawn(owner(), amount);

        (bool ok, ) = owner().call{value: amount}("");
        if (!ok) revert TransferFailed();
    }

    /// @notice Accept direct ETH transfers (bonus pool funding).
    /// @dev NOT pausable — emergency funding must always work.
    receive() external payable {}
}
