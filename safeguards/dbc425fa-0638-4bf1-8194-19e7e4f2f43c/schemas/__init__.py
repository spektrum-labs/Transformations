"""Pydantic schemas for transformation inputs."""

from .confirmedlicensepurchased import ConfirmedlicensepurchasedInput
from .isantiphishingenabled import IsantiphishingenabledInput
from .isdnsconfigured import IsdnsconfiguredInput
from .isemailfilteringenabled import IsemailfilteringenabledInput
from .isemailloggingenabled import IsemailloggingenabledInput
from .isemailsecurityloggingenabled import IsemailsecurityloggingenabledInput
from .ismacroblockingenabled import IsmacroblockingenabledInput
from .ismfaenforcedforusers import IsmfaenforcedforusersInput
from .issafeattachmentsenabled import IssafeattachmentsenabledInput
from .issafelinksenabled import IssafelinksenabledInput
from .isssoenabled import IsssoenabledInput
from .isurlrewriteenabled import IsurlrewriteenabledInput
from .mfa_transform import MfaTransformInput

__all__ = [
    "ConfirmedlicensepurchasedInput",
    "IsantiphishingenabledInput",
    "IsdnsconfiguredInput",
    "IsemailfilteringenabledInput",
    "IsemailloggingenabledInput",
    "IsemailsecurityloggingenabledInput",
    "IsmacroblockingenabledInput",
    "IsmfaenforcedforusersInput",
    "IssafeattachmentsenabledInput",
    "IssafelinksenabledInput",
    "IsssoenabledInput",
    "IsurlrewriteenabledInput",
    "MfaTransformInput",
]
