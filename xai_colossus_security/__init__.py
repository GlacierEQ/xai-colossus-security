"""Public integration contract for the xAI Colossus Security thread.

The package exposes the tested HydraImmune engine and a bounded adapter for
sibling-repository composition.  Neither surface executes network, credential,
firmware, process, physical, or supply-chain mutations.
"""

from .adapter import ColossusSecurityAdapter, SecurityAdapterInputError
from security.hydra_immune import HydraImmune, Threat, ThreatLevel, ThreatType

__all__ = [
    "ColossusSecurityAdapter",
    "HydraImmune",
    "SecurityAdapterInputError",
    "Threat",
    "ThreatLevel",
    "ThreatType",
]
