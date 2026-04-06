"""Pydantic schemas for transformation inputs."""

from .confirmedlicensepurchased import ConfirmedlicensepurchasedInput
from .isantiphishingenabled import IsantiphishingenabledInput
from .isdkimconfigured import IsdkimconfiguredInput
from .isdmarcconfigured import IsdmarcconfiguredInput
from .isemailloggingenabled import IsemailloggingenabledInput
from .isspfconfigured import IsspfconfiguredInput
from .isurlrewriteenabled import IsurlrewriteenabledInput

__all__ = [
    "ConfirmedlicensepurchasedInput",
    "IsantiphishingenabledInput",
    "IsdkimconfiguredInput",
    "IsdmarcconfiguredInput",
    "IsemailloggingenabledInput",
    "IsspfconfiguredInput",
    "IsurlrewriteenabledInput",
]
