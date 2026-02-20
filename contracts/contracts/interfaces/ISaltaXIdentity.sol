// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title ISaltaXIdentity
/// @notice Interface for future ERC-8004 on-chain agent identity.
/// @dev No implementation contract shipped yet — this exists to lock the
///      function signatures so that callers can code against a stable ABI.
interface ISaltaXIdentity {
    /// @notice Register a new agent identity on-chain.
    /// @param registrationPayload ABI-encoded registration data.
    function registerAgent(bytes calldata registrationPayload) external;

    /// @notice Push a reputation update for an agent.
    /// @param reputationData ABI-encoded reputation delta.
    function updateReputation(bytes calldata reputationData) external;

    /// @notice Read the current reputation blob for an agent.
    /// @param agent The agent's address.
    /// @return Opaque ABI-encoded reputation data.
    function getReputation(address agent) external view returns (bytes memory);
}
