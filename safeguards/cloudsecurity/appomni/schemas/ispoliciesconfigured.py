"""Schema for ispoliciesconfigured transformation input."""

from typing import Any, Dict, List, Optional, Union

from pydantic import BaseModel, Field


class PolicyItem(BaseModel):
    """A single security policy entry."""

    enabled: Optional[Union[bool, str]] = Field(
        None,
        description="Whether the policy is enabled. Accepts bool or string ('true', '1', 'yes').",
    )

    class Config:
        extra = "allow"


class IspoliciesconfiguredInput(BaseModel):
    """
    Expected input schema for the ispoliciesconfigured transformation.

    Criteria key: isPoliciesConfigured

    Evaluates that at least one enabled security policy exists in AppOmni.
    The list of policies may appear under 'results', 'data', or 'items'.
    """

    results: Optional[List[PolicyItem]] = Field(
        None,
        description="List of policies (primary key).",
    )
    data: Optional[List[PolicyItem]] = Field(
        None,
        description="List of policies (alternate key).",
    )
    items: Optional[List[PolicyItem]] = Field(
        None,
        description="List of policies (alternate key).",
    )

    class Config:
        extra = "allow"
