"""Schema for ismfaenforced transformation input.

PingFederate's GET /pf-admin-api/v1/authenticationPolicies/default. The transform currently
answers not evaluated; see the note in ismfaenforced.py.
"""
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class AuthnSelectionTree(BaseModel):
    """One authentication policy tree."""

    enabled: Optional[bool] = Field(None, description="Whether this policy tree is enabled")
    rootNode: Optional[Dict[str, Any]] = Field(
        None,
        description=("Root node: an action (e.g. type AUTHN_SOURCE with "
                     "authenticationSource.sourceRef.id naming an adapter instance) and children"),
    )

    class Config:
        extra = "allow"


class IsmfaenforcedInput(BaseModel):
    """Expected input schema for the ismfaenforced transformation. Criteria key: isMFAEnforced"""

    authnSelectionTrees: Optional[List[AuthnSelectionTree]] = Field(
        None, description="The authentication policy trees"
    )

    class Config:
        extra = "allow"
