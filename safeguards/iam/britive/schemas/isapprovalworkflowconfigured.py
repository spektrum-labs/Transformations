"""Schema for isapprovalworkflowconfigured transformation input."""
from typing import Any, Dict, List, Optional, Union

from pydantic import BaseModel, Field


class ApproversRecord(BaseModel):
    """Approvers configuration for a policy."""
    userIds: Optional[List[str]] = Field(None, description="List of approver user IDs")
    users: Optional[List[str]] = Field(None, description="Alternate list of approver users")
    tags: Optional[List[str]] = Field(None, description="List of approver tags")

    class Config:
        extra = "allow"


class PolicyRecord(BaseModel):
    """Individual policy object from Britive profile policies."""
    policyId: Optional[str] = Field(None, description="Policy identifier")
    name: Optional[str] = Field(None, description="Policy name")
    isActive: Optional[Union[bool, str]] = Field(None, description="Whether the policy is active")
    approvalRequired: Optional[Union[bool, str]] = Field(None, description="Whether approval is required for checkout")
    approvers: Optional[ApproversRecord] = Field(None, description="Approvers configuration")
    notificationMedium: Optional[str] = Field(None, description="Notification channel for approval requests")
    timeToApprove: Optional[int] = Field(None, description="Time allowed for approval in minutes")

    class Config:
        extra = "allow"


class IsapprovalworkflowconfiguredInput(BaseModel):
    """Expected input schema for the isapprovalworkflowconfigured transformation. Criteria key: isApprovalWorkflowConfigured"""
    policies: Optional[List[PolicyRecord]] = Field(None, description="List of policy objects")
    data: Optional[List[PolicyRecord]] = Field(None, description="Alternate list of policy objects")

    class Config:
        extra = "allow"
