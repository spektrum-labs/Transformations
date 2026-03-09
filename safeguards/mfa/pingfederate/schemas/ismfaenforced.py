"""Schema for ismfaenforced transformation input."""
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class PolicyTreeNode(BaseModel):
    """A node in an authentication policy tree."""

    class Config:
        extra = "allow"


class AuthenticationPolicyTree(BaseModel):
    """An authentication policy tree within a policy."""

    enabled: Optional[bool] = Field(None, description="Whether this policy tree is enabled")
    rootNode: Optional[Dict[str, Any]] = Field(None, description="Root node of the authentication policy tree")

    class Config:
        extra = "allow"


class AuthenticationPolicy(BaseModel):
    """An individual authentication policy."""

    enabled: Optional[bool] = Field(None, description="Whether this policy is enabled")
    authenticationPolicyTrees: Optional[List[AuthenticationPolicyTree]] = Field(
        None, description="List of authentication policy trees within this policy"
    )

    class Config:
        extra = "allow"


class IsmfaenforcedInput(BaseModel):
    """Expected input schema for the ismfaenforced transformation. Criteria key: isMFAEnforced"""

    authenticationPolicies: Optional[List[AuthenticationPolicy]] = Field(
        None, description="List of authentication policies (primary key)"
    )
    policies: Optional[List[AuthenticationPolicy]] = Field(
        None, description="List of policies (alternate key)"
    )
    items: Optional[List[AuthenticationPolicy]] = Field(
        None, description="List of policy items (alternate key)"
    )

    class Config:
        extra = "allow"
