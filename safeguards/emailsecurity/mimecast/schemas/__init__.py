"""Pydantic schemas for transformation inputs."""

from .confirmedlicensepurchased import ConfirmedlicensepurchasedInput
from .isantiphishingenabled import IsantiphishingenabledInput
from .isdnsconfigured import IsdnsconfiguredInput
from .isemailloggingenabled import IsemailloggingenabledInput
from .isurlrewriteenabled import IsurlrewriteenabledInput

__all__ = [
    "ConfirmedlicensepurchasedInput",
    "IsantiphishingenabledInput",
    "IsdnsconfiguredInput",
    "IsemailloggingenabledInput",
    "IsurlrewriteenabledInput",
]
