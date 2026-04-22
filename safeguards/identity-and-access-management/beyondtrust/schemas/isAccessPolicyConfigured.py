"""Schema for isAccessPolicyConfigured transformation input."""
from typing import List, Optional, Union
from pydantic import BaseModel


class ApprovalWorkflow(BaseModel):
    """Nested approval workflow structure within an access policy."""
    RequiresApproval: Optional[Union[bool, str]] = None

    class Config:
        extra = "allow"


class AccessPolicy(BaseModel):
    """A single access policy entry from the BeyondTrust AccessPolicies endpoint."""
    AccessPolicyID: Optional[int] = None
    Name: Optional[str] = None
    ActiveStatus: Optional[Union[int, str]] = None
    RequireApproval: Optional[Union[bool, str]] = None
    ApprovalWorkflow: Optional[ApprovalWorkflow] = None

    class Config:
        extra = "allow"


class IsAccessPolicyConfiguredInput(BaseModel):
    """Expected input shape for the isAccessPolicyConfigured transformation."""
    AccessPolicies: Optional[List[AccessPolicy]] = None
    items: Optional[List[AccessPolicy]] = None
    results: Optional[List[AccessPolicy]] = None

    class Config:
        extra = "allow"
