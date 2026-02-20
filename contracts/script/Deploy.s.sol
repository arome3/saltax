// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console} from "forge-std/Script.sol";
import {SaltaXStaking} from "../contracts/SaltaXStaking.sol";
import {SaltaXTreasury} from "../contracts/SaltaXTreasury.sol";

/// @title Deploy
/// @notice Deterministic deploy script for SaltaXStaking and SaltaXTreasury.
/// @dev Uses CREATE2 with a salt derived from deployer + chainid for
///      predictable addresses across test/staging/production.
///      Set env vars to skip already-deployed contracts:
///      - STAKING_ADDRESS: skip staking deployment if non-zero
///      - TREASURY_ADDRESS: skip treasury deployment if non-zero
///
///      Usage:
///        forge script script/Deploy.s.sol --rpc-url base --broadcast
contract Deploy is Script {
    // Treasury defaults matching src/config.py TreasuryConfig
    uint256 constant RESERVE_RATIO_BPS = 2000;    // 20%
    uint256 constant BOUNTY_BUDGET_BPS = 6500;     // 65%
    uint256 constant MAX_SINGLE_PAYOUT_WEI = 0.5 ether;

    function run() external {
        uint256 deployerKey = vm.envUint("DEPLOYER_PRIVATE_KEY");
        address deployer = vm.addr(deployerKey);

        console.log("Deployer:", deployer);
        console.log("Chain ID:", block.chainid);

        // Deterministic salt: deployer + chain ID
        bytes32 salt = keccak256(abi.encodePacked(deployer, block.chainid));

        // Check for existing deployments
        address stakingAddr = vm.envOr("STAKING_ADDRESS", address(0));
        address treasuryAddr = vm.envOr("TREASURY_ADDRESS", address(0));

        vm.startBroadcast(deployerKey);

        // ── Staking ──────────────────────────────────────────────────────
        if (stakingAddr == address(0)) {
            SaltaXStaking staking = new SaltaXStaking{salt: salt}(deployer);
            stakingAddr = address(staking);
            console.log("SaltaXStaking deployed at:", stakingAddr);
        } else {
            console.log("SaltaXStaking already deployed at:", stakingAddr);
        }

        // ── Treasury ─────────────────────────────────────────────────────
        if (treasuryAddr == address(0)) {
            SaltaXTreasury treasury = new SaltaXTreasury{salt: salt}(
                deployer,
                RESERVE_RATIO_BPS,
                BOUNTY_BUDGET_BPS,
                MAX_SINGLE_PAYOUT_WEI
            );
            treasuryAddr = address(treasury);
            console.log("SaltaXTreasury deployed at:", treasuryAddr);
        } else {
            console.log("SaltaXTreasury already deployed at:", treasuryAddr);
        }

        vm.stopBroadcast();

        console.log("--- Deployment Summary ---");
        console.log("Staking: ", stakingAddr);
        console.log("Treasury:", treasuryAddr);
    }
}
