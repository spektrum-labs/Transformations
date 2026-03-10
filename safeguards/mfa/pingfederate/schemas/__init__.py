"""Pydantic schemas for transformation inputs."""
from .authtypesallowed import AuthtypesallowedInput
from .confirmedlicensepurchased import ConfirmedlicensepurchasedInput
from .isauthpolicyenabled import IsauthpolicyenabledInput
from .islegacyauthblocked import IslegacyauthblockedInput
from .ismfaenabled import IsmfaenabledInput
from .ismfaenforced import IsmfaenforcedInput
from .ismfaenforced_admins import IsmfaenforcedAdminsInput

__all__ = [
    "AuthtypesallowedInput",
    "ConfirmedlicensepurchasedInput",
    "IsauthpolicyenabledInput",
    "IslegacyauthblockedInput",
    "IsmfaenabledInput",
    "IsmfaenforcedInput",
    "IsmfaenforcedAdminsInput",
]
