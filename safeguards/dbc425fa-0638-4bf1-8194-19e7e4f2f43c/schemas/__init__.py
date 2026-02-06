"""Pydantic schemas for transformation inputs."""

from .confirmedlicensepurchased import ConfirmedlicensepurchasedInput
from .isantiphishingenabled import IsantiphishingenabledInput
from .isdnsconfigured import IsdnsconfiguredInput
from .isemailsecurityloggingenabled import IsemailsecurityloggingenabledInput
from .ismfaenforcedforusers import IsmfaenforcedforusersInput
from .isssoenabled import IsssoenabledInput
from .isurlrewriteenabled import IsurlrewriteenabledInput
from .mfa_transform import MfaTransformInput

__all__ = [
    "ConfirmedlicensepurchasedInput",
    "IsantiphishingenabledInput",
    "IsdnsconfiguredInput",
    "IsemailsecurityloggingenabledInput",
    "IsmfaenforcedforusersInput",
    "IsssoenabledInput",
    "IsurlrewriteenabledInput",
    "MfaTransformInput",
]
