"""Pydantic schemas for transformation inputs."""

from .confirmedlicensepurchased import ConfirmedlicensepurchasedInput
from .isantiphishingenabled import IsantiphishingenabledInput
from .isattachmentdefensesandboxingenabled import IsattachmentdefensesandboxingenabledInput
from .issafelinksenabled import IssafelinksenabledInput
from .issafeattachmentsenabled import IssafeattachmentsenabledInput
from .isdmarcconfigured import IsdmarcconfiguredInput
from .isemailwarningtagsenabled import IsemailwarningtagsenabledInput
from .isautoforwarddisabled import IsautoforwarddisabledInput
from .issmtpauthdisabled import IssmtpauthdisabledInput
from .ismailboxauditingenabled import IsmailboxauditingenabledInput

__all__ = [
    "ConfirmedlicensepurchasedInput",
    "IsantiphishingenabledInput",
    "IsattachmentdefensesandboxingenabledInput",
    "IssafelinksenabledInput",
    "IssafeattachmentsenabledInput",
    "IsdmarcconfiguredInput",
    "IsemailwarningtagsenabledInput",
    "IsautoforwarddisabledInput",
    "IssmtpauthdisabledInput",
    "IsmailboxauditingenabledInput",
]
