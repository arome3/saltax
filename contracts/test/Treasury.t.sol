// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {SaltaXTreasury} from "../contracts/SaltaXTreasury.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";

contract TreasuryTest is Test {
    SaltaXTreasury public treasury;
    address public owner;
    address public recipient;
    address public nonOwner;

    // Config: 20% reserve, 65% bounty budget, 0.5 ETH max single payout
    uint256 constant RESERVE_BPS = 2000;
    uint256 constant BOUNTY_BPS = 6500;
    uint256 constant MAX_PAYOUT = 0.5 ether;

    function setUp() public {
        owner = address(this);
        recipient = makeAddr("recipient");
        nonOwner = makeAddr("nonOwner");

        treasury = new SaltaXTreasury(owner, RESERVE_BPS, BOUNTY_BPS, MAX_PAYOUT);

        // Fund treasury with 10 ETH
        vm.deal(address(treasury), 10 ether);
    }

    // ── Happy Path ───────────────────────────────────────────────────────

    function test_WithdrawWithinAllLimits() public {
        uint256 balBefore = recipient.balance;

        // 0.1 ETH from 10 ETH balance: within max (0.5), reserve (2 ETH), budget (6.5 ETH)
        treasury.withdraw(recipient, 0.1 ether);

        assertEq(recipient.balance, balBefore + 0.1 ether);
        assertEq(address(treasury).balance, 9.9 ether);
    }

    // ── Policy Violation Tests ───────────────────────────────────────────

    function test_ExceedsMaxSinglePayout() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                SaltaXTreasury.PayoutExceedsMaxSingle.selector,
                0.6 ether,
                MAX_PAYOUT
            )
        );
        treasury.withdraw(recipient, 0.6 ether);
    }

    function test_ViolatesReserveRatio() public {
        // With 0.6 ETH balance: reserve = 0.12 ETH. Withdraw 0.5 → remaining 0.1 < 0.12. Fail!
        SaltaXTreasury tiny = new SaltaXTreasury(owner, RESERVE_BPS, BOUNTY_BPS, MAX_PAYOUT);
        vm.deal(address(tiny), 0.6 ether);

        // 0.6 * 2000 / 10000 = 0.12 ETH reserve. 0.6 - 0.5 remaining = 0.1 < 0.12
        vm.expectRevert(
            abi.encodeWithSelector(
                SaltaXTreasury.PayoutViolatesReserve.selector,
                0.1 ether,  // remaining
                0.12 ether  // required reserve
            )
        );
        tiny.withdraw(recipient, 0.5 ether);
    }

    function test_ExceedsBountyBudget() public {
        // With 0.5 ETH balance: budget = 0.5 * 6500 / 10000 = 0.325 ETH
        // Max payout = 0.5 ETH. Withdraw 0.4 > 0.325 → budget violation.
        SaltaXTreasury small = new SaltaXTreasury(owner, RESERVE_BPS, BOUNTY_BPS, MAX_PAYOUT);
        vm.deal(address(small), 0.5 ether);

        vm.expectRevert(
            abi.encodeWithSelector(
                SaltaXTreasury.PayoutExceedsBountyBudget.selector,
                0.4 ether,
                0.325 ether  // 0.5 * 6500 / 10000
            )
        );
        small.withdraw(recipient, 0.4 ether);
    }

    // ── Access Control ───────────────────────────────────────────────────

    function test_NonOwnerWithdrawReverts() public {
        vm.prank(nonOwner);
        vm.expectRevert();
        treasury.withdraw(recipient, 0.1 ether);
    }

    // ── Edge Cases ───────────────────────────────────────────────────────

    function test_ZeroWithdrawReverts() public {
        vm.expectRevert(SaltaXTreasury.ZeroAmount.selector);
        treasury.withdraw(recipient, 0);
    }

    function test_ExactMaxPayoutSucceeds() public {
        // 0.5 ETH from 10 ETH: max single = 0.5 ✓, reserve floor = 2 ETH,
        // remaining 9.5 > 2 ✓, budget = 6.5 ETH, 0.5 < 6.5 ✓
        uint256 balBefore = recipient.balance;
        treasury.withdraw(recipient, MAX_PAYOUT);
        assertEq(recipient.balance, balBefore + MAX_PAYOUT);
    }

    function test_ExactReserveFloorSucceeds() public {
        // Balance = 1 ETH. Reserve = 0.2 ETH. Budget = 0.65 ETH.
        // Withdraw 0.5 ETH → remaining 0.5 ≥ 0.2 ✓, 0.5 ≤ 0.5 max ✓, 0.5 ≤ 0.65 budget ✓
        SaltaXTreasury exact = new SaltaXTreasury(owner, RESERVE_BPS, BOUNTY_BPS, MAX_PAYOUT);
        vm.deal(address(exact), 1 ether);

        uint256 balBefore = recipient.balance;
        exact.withdraw(recipient, 0.5 ether);
        assertEq(recipient.balance, balBefore + 0.5 ether);
    }

    function test_EmptyTreasuryWithdrawReverts() public {
        SaltaXTreasury empty = new SaltaXTreasury(owner, RESERVE_BPS, BOUNTY_BPS, MAX_PAYOUT);
        // No funding — balance is 0

        // Zero amount reverts with ZeroAmount
        vm.expectRevert(SaltaXTreasury.ZeroAmount.selector);
        empty.withdraw(recipient, 0);

        // Non-zero from empty treasury reverts with InsufficientBalance
        vm.expectRevert(
            abi.encodeWithSelector(
                SaltaXTreasury.InsufficientBalance.selector,
                0.1 ether,
                0
            )
        );
        empty.withdraw(recipient, 0.1 ether);
    }

    // ── Integration ──────────────────────────────────────────────────────

    function test_SequentialWithdrawals() public {
        // 10 ETH starting balance. Withdraw 0.5 ETH five times.
        for (uint256 i = 0; i < 5; i++) {
            treasury.withdraw(recipient, 0.5 ether);
        }
        // Balance should be 7.5 ETH
        assertEq(address(treasury).balance, 7.5 ether);

        // Budget on 7.5 = 4.875 ETH. Reserve = 1.5 ETH. Still well within limits.
        treasury.withdraw(recipient, 0.5 ether);
        assertEq(address(treasury).balance, 7 ether);
    }

    // ── Receive Tests ────────────────────────────────────────────────────

    function test_ReceiveETHAndEmitEvent() public {
        address funder = makeAddr("funder");
        vm.deal(funder, 1 ether);

        vm.prank(funder);
        vm.expectEmit(true, false, false, true);
        emit SaltaXTreasury.FundsReceived(funder, 1 ether);
        (bool ok, ) = address(treasury).call{value: 1 ether}("");
        assertTrue(ok);
        assertEq(address(treasury).balance, 11 ether);
    }

    // ── Regression: Issue 7 — zero address guard ─────────────────────────

    function test_ZeroAddressReverts() public {
        vm.expectRevert(SaltaXTreasury.ZeroAddress.selector);
        treasury.withdraw(address(0), 0.1 ether);
    }

    // ── Regression: Issue 1 — renounceOwnership disabled ─────────────────

    function test_RenounceOwnershipReverts() public {
        vm.expectRevert(SaltaXTreasury.RenounceOwnershipDisabled.selector);
        treasury.renounceOwnership();
    }

    // ── Regression: Issue 5 — constructor validation ─────────────────────

    function test_ConstructorRejectsReserveOver100Pct() public {
        vm.expectRevert(abi.encodeWithSelector(SaltaXTreasury.InvalidReserveRatio.selector, 10_001));
        new SaltaXTreasury(owner, 10_001, BOUNTY_BPS, MAX_PAYOUT);
    }

    function test_ConstructorRejectsBountyOver100Pct() public {
        vm.expectRevert(abi.encodeWithSelector(SaltaXTreasury.InvalidBountyBudget.selector, 10_001));
        new SaltaXTreasury(owner, RESERVE_BPS, 10_001, MAX_PAYOUT);
    }

    function test_ConstructorRejectsZeroMaxPayout() public {
        vm.expectRevert(SaltaXTreasury.InvalidMaxPayout.selector);
        new SaltaXTreasury(owner, RESERVE_BPS, BOUNTY_BPS, 0);
    }

    function test_ConstructorAcceptsExact100PctReserve() public {
        // 10000 bps = 100% — valid boundary
        SaltaXTreasury full = new SaltaXTreasury(owner, 10_000, BOUNTY_BPS, MAX_PAYOUT);
        assertEq(full.reserveRatioBps(), 10_000);
    }

    // ── Regression: Issue 4 — pause blocks withdraw ──────────────────────

    function test_PauseBlocksWithdraw() public {
        // Pause the contract
        treasury.pause();

        // Withdraw should revert while paused
        vm.expectRevert(Pausable.EnforcedPause.selector);
        treasury.withdraw(recipient, 0.1 ether);

        // Unpause — withdraw should succeed
        treasury.unpause();

        uint256 balBefore = recipient.balance;
        treasury.withdraw(recipient, 0.1 ether);
        assertEq(recipient.balance, balBefore + 0.1 ether);
    }

    // ── Fuzz Tests ───────────────────────────────────────────────────────

    function testFuzz_WithdrawWithinLimits(uint256 amount) public {
        // Bound to valid range: 1 wei to MAX_PAYOUT
        amount = bound(amount, 1, MAX_PAYOUT);

        // With 10 ETH balance, reserve = 2 ETH, budget = 6.5 ETH.
        // Any amount <= 0.5 ETH will pass all three checks.
        uint256 balBefore = recipient.balance;
        treasury.withdraw(recipient, amount);
        assertEq(recipient.balance, balBefore + amount);
    }

    function testFuzz_RejectOverMaxPayout(uint256 amount) public {
        // Bound above MAX_PAYOUT to ensure rejection
        amount = bound(amount, MAX_PAYOUT + 1, type(uint96).max);

        vm.expectRevert();
        treasury.withdraw(recipient, amount);
    }
}
