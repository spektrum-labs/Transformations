"""Schema for isviolationalertingenabled transformation input."""

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class NotificationItem(BaseModel):
    """A single notification rule entry."""

    enabled: Optional[bool] = Field(
        None,
        description="Whether the notification rule is enabled.",
    )
    channel: Optional[str] = Field(
        None,
        description="Notification channel, e.g. 'email', 'slack', 'webhook'.",
    )

    class Config:
        extra = "allow"


class IsviolationalertingenabledInput(BaseModel):
    """
    Expected input schema for the isviolationalertingenabled transformation.

    Criteria key: isViolationAlertingEnabled

    Evaluates that at least one notification rule is configured and enabled
    in AppOmni. The list of notifications may appear under 'results',
    'data', or 'items'.
    """

    results: Optional[List[NotificationItem]] = Field(
        None,
        description="List of notification rules (primary key).",
    )
    data: Optional[List[NotificationItem]] = Field(
        None,
        description="List of notification rules (alternate key).",
    )
    items: Optional[List[NotificationItem]] = Field(
        None,
        description="List of notification rules (alternate key).",
    )

    class Config:
        extra = "allow"
