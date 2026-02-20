// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {SaltaXStaking} from "../contracts/SaltaXStaking.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";

contract StakingTest is Test {
    SaltaXStaking public staking;
    address public owner;
    address public contributor;
    address public nonOwner;

    bytes32 constant STAKE_ID = keccak256("stake-1");
    bytes32 constant PR_ID = keccak256("pr-42");
    uint256 constant STAKE_AMOUNT = 0.1 ether;

    // ── Reentrancy attack state ──────────────────────────────────────────
    bool private reenterOnReceive;
    bytes32 private reenterStakeId;

    // Test contract is the owner — must accept ETH from withdrawSlashed.
    // Also serves as reentrancy attacker: re-enters releaseStake on receive.
    receive() external payable {
        if (reenterOnReceive) {
            reenterOnReceive = false; // prevent infinite loop
            staking.releaseStake(reenterStakeId, 0);
        }
    }

    function setUp() public {
        owner = address(this);
        contributor = makeAddr("contributor");
        nonOwner = makeAddr("nonOwner");

        staking = new SaltaXStaking(owner);

        // Fund contributor for deposits
        vm.deal(contributor, 10 ether);
        // Fund contract for bonuses
        vm.deal(address(staking), 5 ether);
    }

    // ── Lifecycle Tests ──────────────────────────────────────────────────

    function test_DepositAndRelease() public {
        vm.prank(contributor);
        staking.depositStake{value: STAKE_AMOUNT}(STAKE_ID, PR_ID);

        uint256 balBefore = contributor.balance;
        uint256 bonus = 0.01 ether;
        staking.releaseStake(STAKE_ID, bonus);

        assertEq(contributor.balance, balBefore + STAKE_AMOUNT + bonus);
    }

    function test_DepositAndSlash50() public {
        vm.prank(contributor);
        staking.depositStake{value: STAKE_AMOUNT}(STAKE_ID, PR_ID);

        uint256 balBefore = contributor.balance;
        staking.slashStake(STAKE_ID, 50);

        // Contributor gets back 50%
        assertEq(contributor.balance, balBefore + STAKE_AMOUNT / 2);
        // Slashed funds accumulated
        assertEq(staking.totalSlashedFunds(), STAKE_AMOUNT / 2);
    }

    function test_DepositAndRefund() public {
        vm.prank(contributor);
        staking.depositStake{value: STAKE_AMOUNT}(STAKE_ID, PR_ID);

        uint256 balBefore = contributor.balance;
        staking.refundStake(STAKE_ID);

        assertEq(contributor.balance, balBefore + STAKE_AMOUNT);
    }

    function test_DepositSlashAndWithdrawSlashed() public {
        vm.prank(contributor);
        staking.depositStake{value: STAKE_AMOUNT}(STAKE_ID, PR_ID);

        staking.slashStake(STAKE_ID, 100);
        assertEq(staking.totalSlashedFunds(), STAKE_AMOUNT);

        uint256 ownerBalBefore = owner.balance;
        staking.withdrawSlashed(STAKE_AMOUNT);

        assertEq(owner.balance, ownerBalBefore + STAKE_AMOUNT);
        assertEq(staking.totalSlashedFunds(), 0);
    }

    // ── Access Control Tests ─────────────────────────────────────────────

    function test_NonOwnerCannotRelease() public {
        vm.prank(contributor);
        staking.depositStake{value: STAKE_AMOUNT}(STAKE_ID, PR_ID);

        vm.prank(nonOwner);
        vm.expectRevert();
        staking.releaseStake(STAKE_ID, 0);
    }

    function test_NonOwnerCannotSlash() public {
        vm.prank(contributor);
        staking.depositStake{value: STAKE_AMOUNT}(STAKE_ID, PR_ID);

        vm.prank(nonOwner);
        vm.expectRevert();
        staking.slashStake(STAKE_ID, 50);
    }

    function test_NonOwnerCannotRefund() public {
        vm.prank(contributor);
        staking.depositStake{value: STAKE_AMOUNT}(STAKE_ID, PR_ID);

        vm.prank(nonOwner);
        vm.expectRevert();
        staking.refundStake(STAKE_ID);
    }

    function test_NonOwnerCannotWithdrawSlashed() public {
        vm.prank(nonOwner);
        vm.expectRevert();
        staking.withdrawSlashed(1 ether);
    }

    // ── Edge Cases ───────────────────────────────────────────────────────

    function test_ZeroDepositReverts() public {
        vm.prank(contributor);
        vm.expectRevert(SaltaXStaking.StakeMustBePositive.selector);
        staking.depositStake{value: 0}(STAKE_ID, PR_ID);
    }

    function test_DoubleDepositReverts() public {
        vm.prank(contributor);
        staking.depositStake{value: STAKE_AMOUNT}(STAKE_ID, PR_ID);

        vm.prank(contributor);
        vm.expectRevert(abi.encodeWithSelector(SaltaXStaking.StakeAlreadyExists.selector, STAKE_ID));
        staking.depositStake{value: STAKE_AMOUNT}(STAKE_ID, PR_ID);
    }

    function test_Slash100Percent() public {
        vm.prank(contributor);
        staking.depositStake{value: STAKE_AMOUNT}(STAKE_ID, PR_ID);

        uint256 balBefore = contributor.balance;
        staking.slashStake(STAKE_ID, 100);

        // Full slash — contributor gets nothing back
        assertEq(contributor.balance, balBefore);
        assertEq(staking.totalSlashedFunds(), STAKE_AMOUNT);
    }

    function test_SlashOver100Reverts() public {
        vm.prank(contributor);
        staking.depositStake{value: STAKE_AMOUNT}(STAKE_ID, PR_ID);

        vm.expectRevert(abi.encodeWithSelector(SaltaXStaking.InvalidSlashPercent.selector, 101));
        staking.slashStake(STAKE_ID, 101);
    }

    function test_DoubleResolveReverts() public {
        vm.prank(contributor);
        staking.depositStake{value: STAKE_AMOUNT}(STAKE_ID, PR_ID);

        staking.releaseStake(STAKE_ID, 0);

        vm.expectRevert(abi.encodeWithSelector(SaltaXStaking.StakeAlreadyResolved.selector, STAKE_ID));
        staking.releaseStake(STAKE_ID, 0);
    }

    function test_ReleaseNonexistentStakeReverts() public {
        bytes32 fake = keccak256("nonexistent");
        vm.expectRevert(abi.encodeWithSelector(SaltaXStaking.StakeNotFound.selector, fake));
        staking.releaseStake(fake, 0);
    }

    function test_PartialRelease() public {
        // Deploy a fresh staking contract with no bonus pool
        SaltaXStaking lean = new SaltaXStaking(owner);

        vm.prank(contributor);
        lean.depositStake{value: STAKE_AMOUNT}(STAKE_ID, PR_ID);

        // Request a release with a large bonus the contract can't cover
        uint256 bonus = 10 ether;

        // The contract only has STAKE_AMOUNT, so it does a partial release
        uint256 balBefore = contributor.balance;
        lean.releaseStake(STAKE_ID, bonus);

        // Contributor receives whatever the contract had
        assertEq(contributor.balance, balBefore + STAKE_AMOUNT);
    }

    // ── Reentrancy Tests ─────────────────────────────────────────────────

    /// @dev address(this) is BOTH the owner and the contributor.
    ///      When releaseStake sends ETH back to address(this), receive()
    ///      re-enters releaseStake. onlyOwner passes (we ARE the owner),
    ///      so only nonReentrant blocks it — proving the actual guard works.
    ///
    ///      The inner call reverts with ReentrancyGuardReentrantCall, but
    ///      this propagates through receive(), causing the outer low-level
    ///      call to fail → TransferFailed. The trace confirms the guard:
    ///        receive() → releaseStake() → [Revert] ReentrancyGuardReentrantCall()
    function test_ReentrancyOnRelease() public {
        bytes32 attackId1 = keccak256("attack-1");
        bytes32 attackId2 = keccak256("attack-2");

        // address(this) deposits as contributor (we're also the owner)
        staking.depositStake{value: 0.1 ether}(attackId1, PR_ID);
        staking.depositStake{value: 0.1 ether}(attackId2, PR_ID);

        // Arm the re-entrance trigger
        reenterOnReceive = true;
        reenterStakeId = attackId2;

        // Release first stake — ETH comes back to address(this) → receive()
        // fires → tries releaseStake(attackId2) → nonReentrant blocks it →
        // receive() reverts → outer call sees TransferFailed
        vm.expectRevert(SaltaXStaking.TransferFailed.selector);
        staking.releaseStake(attackId1, 0);
    }

    /// @dev Same pattern for slashStake — partial return sends ETH to
    ///      address(this), which tries to re-enter via releaseStake.
    ///      Inner revert is ReentrancyGuardReentrantCall (visible in trace),
    ///      outer revert is TransferFailed (receive() propagates the failure).
    function test_ReentrancyOnSlash() public {
        bytes32 attackId1 = keccak256("attack-slash-1");
        bytes32 attackId2 = keccak256("attack-slash-2");

        // address(this) deposits as contributor
        staking.depositStake{value: 0.1 ether}(attackId1, PR_ID);
        staking.depositStake{value: 0.1 ether}(attackId2, PR_ID);

        // Arm the re-entrance trigger
        reenterOnReceive = true;
        reenterStakeId = attackId2;

        // Slash with 50% return — ETH comes to address(this) → receive() re-enters
        vm.expectRevert(SaltaXStaking.TransferFailed.selector);
        staking.slashStake(attackId1, 50);
    }

    // ── Event Tests ──────────────────────────────────────────────────────

    function test_StakeDepositedEvent() public {
        vm.prank(contributor);
        vm.expectEmit(true, true, false, true);
        emit SaltaXStaking.StakeDeposited(STAKE_ID, contributor, STAKE_AMOUNT, PR_ID);
        staking.depositStake{value: STAKE_AMOUNT}(STAKE_ID, PR_ID);
    }

    function test_StakeReleasedEvent() public {
        vm.prank(contributor);
        staking.depositStake{value: STAKE_AMOUNT}(STAKE_ID, PR_ID);

        uint256 bonus = 0.01 ether;
        vm.expectEmit(true, true, false, true);
        emit SaltaXStaking.StakeReleased(STAKE_ID, contributor, STAKE_AMOUNT, bonus);
        staking.releaseStake(STAKE_ID, bonus);
    }

    function test_SlashedWithdrawnEvent() public {
        vm.prank(contributor);
        staking.depositStake{value: STAKE_AMOUNT}(STAKE_ID, PR_ID);

        staking.slashStake(STAKE_ID, 100);

        vm.expectEmit(true, false, false, true);
        emit SaltaXStaking.SlashedWithdrawn(owner, STAKE_AMOUNT);
        staking.withdrawSlashed(STAKE_AMOUNT);
    }

    // ── Accumulator Tests ────────────────────────────────────────────────

    function test_WithdrawMoreThanSlashedReverts() public {
        vm.prank(contributor);
        staking.depositStake{value: STAKE_AMOUNT}(STAKE_ID, PR_ID);

        staking.slashStake(STAKE_ID, 50);
        uint256 slashed = staking.totalSlashedFunds();

        vm.expectRevert(
            abi.encodeWithSelector(
                SaltaXStaking.InsufficientSlashedFunds.selector,
                slashed + 1,
                slashed
            )
        );
        staking.withdrawSlashed(slashed + 1);
    }

    // ── Receive Tests ────────────────────────────────────────────────────

    function test_AcceptsDirectETH() public {
        uint256 balBefore = address(staking).balance;
        (bool ok, ) = address(staking).call{value: 1 ether}("");
        assertTrue(ok);
        assertEq(address(staking).balance, balBefore + 1 ether);
    }

    // ── Ownership Tests ──────────────────────────────────────────────────

    function test_Ownable2StepTransfer() public {
        address newOwner = makeAddr("newOwner");

        // Step 1: current owner initiates transfer
        staking.transferOwnership(newOwner);
        // Owner is still the old owner until acceptance
        assertEq(staking.owner(), owner);

        // Step 2: new owner accepts
        vm.prank(newOwner);
        staking.acceptOwnership();
        assertEq(staking.owner(), newOwner);

        // New owner can call protected functions
        vm.prank(contributor);
        staking.depositStake{value: STAKE_AMOUNT}(STAKE_ID, PR_ID);

        vm.prank(newOwner);
        staking.refundStake(STAKE_ID);
    }

    // ── View Function Tests ──────────────────────────────────────────────

    function test_StakesViewFunction() public {
        vm.prank(contributor);
        staking.depositStake{value: STAKE_AMOUNT}(STAKE_ID, PR_ID);

        // stakes() auto-generated getter returns fields in struct order:
        // (address contributor, uint256 amount, bytes32 prId, bool resolved, uint256 depositedAt)
        // This MUST match the Python ABI at src/staking/contract.py:89-95
        (
            address retContributor,
            uint256 retAmount,
            bytes32 retPrId,
            bool retResolved,
            uint256 retDepositedAt
        ) = staking.stakes(STAKE_ID);

        assertEq(retContributor, contributor);
        assertEq(retAmount, STAKE_AMOUNT);
        assertEq(retPrId, PR_ID);
        assertEq(retResolved, false);
        assertEq(retDepositedAt, block.timestamp);
    }

    // ── Regression: Issue 8 — slash percent 0 must revert ────────────────

    function test_SlashZeroReverts() public {
        vm.prank(contributor);
        staking.depositStake{value: STAKE_AMOUNT}(STAKE_ID, PR_ID);

        vm.expectRevert(abi.encodeWithSelector(SaltaXStaking.InvalidSlashPercent.selector, 0));
        staking.slashStake(STAKE_ID, 0);
    }

    // ── Regression: Issue 1 — renounceOwnership disabled ─────────────────

    function test_RenounceOwnershipReverts() public {
        vm.expectRevert(SaltaXStaking.RenounceOwnershipDisabled.selector);
        staking.renounceOwnership();
    }

    // ── Regression: Issue 4 — pause blocks operations ────────────────────

    function test_PauseBlocksDeposit() public {
        // Pause the contract
        staking.pause();

        // Deposit should revert while paused
        vm.prank(contributor);
        vm.expectRevert(Pausable.EnforcedPause.selector);
        staking.depositStake{value: STAKE_AMOUNT}(STAKE_ID, PR_ID);

        // Unpause — deposit should succeed
        staking.unpause();

        vm.prank(contributor);
        staking.depositStake{value: STAKE_AMOUNT}(STAKE_ID, PR_ID);

        (address retContributor,,,, ) = staking.stakes(STAKE_ID);
        assertEq(retContributor, contributor);
    }

    // ── Fuzz Tests ───────────────────────────────────────────────────────

    function testFuzz_DepositAndRelease(uint256 amount, uint256 bonus) public {
        amount = bound(amount, 1, 10 ether);
        bonus = bound(bonus, 0, 10 ether);

        vm.deal(contributor, amount);
        vm.deal(address(staking), bonus);

        bytes32 fuzzId = keccak256(abi.encodePacked("fuzz-dr", amount, bonus));

        vm.prank(contributor);
        staking.depositStake{value: amount}(fuzzId, PR_ID);

        uint256 balBefore = contributor.balance;
        staking.releaseStake(fuzzId, bonus);

        // Contributor gets back stake + bonus (or partial if underfunded)
        uint256 expectedReturn = amount + bonus;
        uint256 actualReturn = contributor.balance - balBefore;

        // Either full return or partial (contract sends what it has)
        assertTrue(actualReturn > 0);
        assertTrue(actualReturn <= expectedReturn);
    }

    function testFuzz_SlashPercent(uint256 amount, uint8 rawPct) public {
        amount = bound(amount, 1, 10 ether);
        uint256 pct = bound(uint256(rawPct), 1, 100);

        vm.deal(contributor, amount);

        bytes32 fuzzId = keccak256(abi.encodePacked("fuzz-sp", amount, pct));

        vm.prank(contributor);
        staking.depositStake{value: amount}(fuzzId, PR_ID);

        uint256 balBefore = contributor.balance;
        staking.slashStake(fuzzId, pct);

        uint256 expectedSlash = (amount * pct) / 100;
        uint256 expectedReturn = amount - expectedSlash;

        assertEq(contributor.balance, balBefore + expectedReturn);
        assertEq(staking.totalSlashedFunds(), expectedSlash);
    }

    function testFuzz_DepositAmounts(uint256 amount) public {
        amount = bound(amount, 1, 100 ether);
        vm.deal(contributor, amount);

        bytes32 fuzzId = keccak256(abi.encodePacked("fuzz-da", amount));

        vm.prank(contributor);
        staking.depositStake{value: amount}(fuzzId, PR_ID);

        (, uint256 retAmount,,, ) = staking.stakes(fuzzId);
        assertEq(retAmount, amount);
    }
}
