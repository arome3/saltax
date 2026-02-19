"""Identity subsystem — on-chain agent registration and reputation."""

from src.identity.bridge_client import AlreadyRegisteredError, IdentityBridgeClient
from src.identity.registration import IdentityRegistrar
from src.identity.reputation import ReputationEvent, ReputationManager

__all__ = [
    "AlreadyRegisteredError",
    "IdentityBridgeClient",
    "IdentityRegistrar",
    "ReputationEvent",
    "ReputationManager",
]
