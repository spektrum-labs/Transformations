"""Schema for isemailloggingenabled transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class Policy(BaseModel):
    """Anti-spoofing bypass policy details."""
    description: Optional[str] = None
    fromPart: Optional[str] = None
    fromType: Optional[str] = None
    toType: Optional[str] = None
    enabled: Optional[bool] = None
    enforced: Optional[bool] = None
    override: Optional[bool] = None
    bidirectional: Optional[bool] = None
    conditions: Optional[Dict[str, Any]] = None

    class Config:
        extra = "allow"


class AntiSpoofBypassEntry(BaseModel):
    """A single anti-spoofing bypass policy entry."""
    id: Optional[str] = None
    policy: Optional[Policy] = None

    class Config:
        extra = "allow"


class IsemailloggingenabledInput(BaseModel):
    """
    Expected input schema for the isemailloggingenabled transformation.
    Criteria key: isEmailLoggingEnabled

    Note: After API response parsing, the Mimecast anti-spoofing bypass
    policy response is unwrapped from the 'data' key, yielding a list of
    AntiSpoofBypassEntry entries. Schema validation may report an error
    for list inputs. The transformation handles both list and dict formats.
    """

    data: Optional[List[AntiSpoofBypassEntry]] = None

    class Config:
        extra = "allow"
