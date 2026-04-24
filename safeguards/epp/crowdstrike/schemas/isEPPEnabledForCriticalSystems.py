"""Schema for isEPPEnabledForCriticalSystems transformation input."""
from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, Field


class HostGroup(BaseModel):
    """A host group assigned to a prevention policy."""
    id: Optional[str] = Field(default=None)
    name: Optional[str] = Field(default=None)
    group_type: Optional[str] = Field(default=None)

    class Config:
        extra = "allow"


class PreventionPolicy(BaseModel):
    """A single CrowdStrike prevention policy resource."""
    id: Optional[str] = Field(default=None)
    name: Optional[str] = Field(default=None)
    enabled: Optional[Union[bool, str]] = Field(default=None, description="Whether the policy is active. May be a bool or string '0'/'1'/'true'/'false'.")
    groups: Optional[List[Any]] = Field(default=None, description="Host groups assigned to this policy")
    platform_name: Optional[str] = Field(default=None)
    description: Optional[str] = Field(default=None)
    prevention_settings: Optional[List[Any]] = Field(default=None)

    class Config:
        extra = "allow"


class GetPreventionPoliciesResult(BaseModel):
    """Shape returned by the getPreventionPolicies method."""
    resources: Optional[List[PreventionPolicy]] = Field(default=None)

    class Config:
        extra = "allow"


class IsEPPEnabledForCriticalSystemsInput(BaseModel):
    """Expected input shape for the isEPPEnabledForCriticalSystems transformation.

    The workflow merges getPreventionPolicies (and others) into a dict keyed by method name.
    The transformation reads getPreventionPolicies.resources (or a flat top-level resources
    list for legacy inputs).
    """
    getPreventionPolicies: Optional[GetPreventionPoliciesResult] = Field(default=None, description="Merged getPreventionPolicies result")
    resources: Optional[List[PreventionPolicy]] = Field(default=None, description="Flat resources list (legacy / direct API format)")

    class Config:
        extra = "allow"
