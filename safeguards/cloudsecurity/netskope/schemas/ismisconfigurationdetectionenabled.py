"""Schema for ismisconfigurationdetectionenabled transformation input."""

from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, Field


class NetskopePolicyAlert(BaseModel):
    """Single policy alert from /api/v2/events/data/alert?type=policy."""

    alert_type: Optional[str] = Field(
        default=None,
        description="Netskope alert type - expected to be 'policy' for real-time / API policy hits"
    )
    type: Optional[str] = Field(
        default=None,
        description="Alternate alert type field"
    )
    severity: Optional[str] = Field(
        default=None,
        description="Alert severity (low, medium, high, critical)"
    )
    severity_level: Optional[Union[str, int]] = Field(
        default=None,
        description="Alternate severity field"
    )
    policy: Optional[str] = Field(
        default=None,
        description="Netskope policy that matched the activity"
    )
    policy_name: Optional[str] = Field(
        default=None,
        description="Alternate policy name field"
    )
    profile: Optional[str] = Field(
        default=None,
        description="DLP / threat protection profile name"
    )
    action: Optional[str] = Field(
        default=None,
        description="Enforcement action taken (alert, block, quarantine, etc.)"
    )
    policy_action: Optional[str] = Field(
        default=None,
        description="Alternate enforcement action field"
    )
    app: Optional[str] = Field(
        default=None,
        description="Application targeted by the policy"
    )
    application: Optional[str] = Field(
        default=None,
        description="Alternate application name field"
    )
    appname: Optional[str] = Field(
        default=None,
        description="Alternate application name field"
    )
    user: Optional[str] = Field(
        default=None,
        description="User that triggered the policy hit"
    )
    activity: Optional[str] = Field(
        default=None,
        description="Activity (upload, download, share, etc.)"
    )
    timestamp: Optional[int] = Field(
        default=None,
        description="Epoch timestamp of the alert"
    )

    class Config:
        extra = "allow"


class IsmisconfigurationdetectionenabledInput(BaseModel):
    """
    Expected input schema for the ismisconfigurationdetectionenabled transformation.
    Criteria key: isMisconfigurationDetectionEnabled

    Validates policy enforcement and misconfiguration detection via
    /api/v2/events/data/alert?type=policy.
    """

    ok: Optional[Union[int, bool]] = Field(
        default=None,
        description="Netskope response status flag (1 = success)"
    )
    status: Optional[str] = Field(
        default=None,
        description="Top-level status field"
    )
    result: Optional[List[NetskopePolicyAlert]] = Field(
        default=None,
        description="Array of policy alerts returned by Netskope REST API v2"
    )
    data: Optional[List[NetskopePolicyAlert]] = Field(
        default=None,
        description="Alternate alerts array"
    )
    alerts: Optional[List[NetskopePolicyAlert]] = Field(
        default=None,
        description="Alternate alerts array"
    )
    items: Optional[List[NetskopePolicyAlert]] = Field(
        default=None,
        description="Alternate alerts array"
    )
    value: Optional[List[NetskopePolicyAlert]] = Field(
        default=None,
        description="Alternate alerts array"
    )
    total: Optional[int] = Field(
        default=None,
        description="Total alerts returned by the response"
    )

    class Config:
        extra = "allow"
