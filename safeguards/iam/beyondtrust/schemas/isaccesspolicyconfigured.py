"""Schema for isaccesspolicyconfigured transformation input."""

from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, Field


class ApprovalWorkflow(BaseModel):
    """Nested approval workflow structure within an access policy."""
    RequiresApproval: Optional[Union[bool, str]] = None

    class Config:
        extra = "allow"


class AccessPolicy(BaseModel):
    """A single access policy entry."""
    ActiveStatus: Optional[Union[int, str]] = None
    RequireApproval: Optional[Union[bool, str]] = None
    ApprovalWorkflow: Optional[ApprovalWorkflow] = None

    class Config:
        extra = "allow"


class IsaccesspolicyconfiguredInput(BaseModel):
    """
    Expected input schema for the isaccesspolicyconfigured transformation.
    Criteria key: isAccessPolicyConfigured
    """
    AccessPolicies: Optional[List[AccessPolicy]] = None
    items: Optional[List[AccessPolicy]] = None
    results: Optional[List[AccessPolicy]] = None

    class Config:
        extra = "allow"
