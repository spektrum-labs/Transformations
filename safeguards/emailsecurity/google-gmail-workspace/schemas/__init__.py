"""Schema registry for this vendor's transformations."""

from .isDKIMConfigured import IsDKIMConfiguredInput
from .isMFAEnforcedForUsers import IsMFAEnforcedForUsersInput

__all__ = [
    "IsDKIMConfiguredInput",
    "IsMFAEnforcedForUsersInput",
]
