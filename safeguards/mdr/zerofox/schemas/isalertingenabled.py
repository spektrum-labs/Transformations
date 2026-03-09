"""Schema for isalertingenabled transformation input."""
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class PolicyNotifications(BaseModel):
    """Notification configuration for a policy."""
    email: Optional[List[str]] = Field(None, description="List of email addresses for notifications")
    webhook: Optional[str] = Field(None, description="Webhook URL for notifications")

    class Config:
        extra = "allow"


class AlertPolicy(BaseModel):
    """A policy with notification configuration."""
    notifications: Optional[PolicyNotifications] = Field(None, description="Notification channels configured for this policy")

    class Config:
        extra = "allow"


class IsalertingenabledInput(BaseModel):
    """Expected input schema for the isalertingenabled transformation. Criteria key: isAlertingEnabled"""
    policies: Optional[List[AlertPolicy]] = Field(None, description="List of policies (also checked as 'results' or 'items')")
    results: Optional[List[AlertPolicy]] = Field(None, description="Alternate key for policies list")
    items: Optional[List[AlertPolicy]] = Field(None, description="Alternate key for policies list")

    class Config:
        extra = "allow"
