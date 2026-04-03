"""Schema for isurlrewriteenabled transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class Policy(BaseModel):
    """Address alteration policy details."""
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


class AddressAlterationSet(BaseModel):
    """A single address alteration set entry."""
    addressAlterationSetId: Optional[str] = None
    id: Optional[str] = None
    policy: Optional[Policy] = None

    class Config:
        extra = "allow"


class IsurlrewriteenabledInput(BaseModel):
    """
    Expected input schema for the isurlrewriteenabled transformation.
    Criteria key: isURLRewriteEnabled

    Note: After API response parsing, the Mimecast address alteration sets
    response is unwrapped from the 'data' key, yielding a list of
    AddressAlterationSet entries. Schema validation may report an error
    for list inputs since BaseModel expects dict input. The transformation
    handles both list and dict formats.
    """

    data: Optional[List[AddressAlterationSet]] = None

    class Config:
        extra = "allow"
