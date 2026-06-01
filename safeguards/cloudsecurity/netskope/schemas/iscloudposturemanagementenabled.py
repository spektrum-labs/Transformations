"""Schema for iscloudposturemanagementenabled transformation input."""

from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, Field


class NetskopeSecurityAssessmentAlert(BaseModel):
    """Single security assessment alert from /api/v2/events/data/alert?type=securityassessment."""

    alert_type: Optional[str] = Field(
        default=None,
        description="Netskope alert type - expected to be 'securityassessment' for CSPM/SSPM findings"
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
    timestamp: Optional[int] = Field(
        default=None,
        description="Epoch timestamp of the alert"
    )
    alert_timestamp: Optional[int] = Field(
        default=None,
        description="Alternate alert timestamp field"
    )
    policy: Optional[str] = Field(
        default=None,
        description="Policy that triggered the alert"
    )
    profile: Optional[str] = Field(
        default=None,
        description="Posture profile that triggered the alert"
    )
    rule_name: Optional[str] = Field(
        default=None,
        description="Specific posture rule that produced the finding"
    )
    service: Optional[str] = Field(
        default=None,
        description="Cloud service the finding relates to (e.g., 'aws', 'azure', 'salesforce')"
    )
    cloud_provider: Optional[str] = Field(
        default=None,
        description="Alternate cloud provider field"
    )
    app: Optional[str] = Field(
        default=None,
        description="Application associated with the alert"
    )
    resource: Optional[str] = Field(
        default=None,
        description="Cloud resource that the finding relates to"
    )
    region: Optional[str] = Field(
        default=None,
        description="Cloud region for the resource"
    )

    class Config:
        extra = "allow"


class IscloudposturemanagementenabledInput(BaseModel):
    """
    Expected input schema for the iscloudposturemanagementenabled transformation.
    Criteria key: isCloudPostureManagementEnabled

    Validates CSPM/SSPM module is licensed and active via
    /api/v2/events/data/alert?type=securityassessment.
    """

    ok: Optional[Union[int, bool]] = Field(
        default=None,
        description="Netskope response status flag (1 = success)"
    )
    status: Optional[str] = Field(
        default=None,
        description="Top-level status field (e.g., 'success')"
    )
    result: Optional[List[NetskopeSecurityAssessmentAlert]] = Field(
        default=None,
        description="Array of security assessment alerts returned by Netskope REST API v2"
    )
    data: Optional[List[NetskopeSecurityAssessmentAlert]] = Field(
        default=None,
        description="Alternate alerts array"
    )
    alerts: Optional[List[NetskopeSecurityAssessmentAlert]] = Field(
        default=None,
        description="Alternate alerts array"
    )
    items: Optional[List[NetskopeSecurityAssessmentAlert]] = Field(
        default=None,
        description="Alternate alerts array"
    )
    value: Optional[List[NetskopeSecurityAssessmentAlert]] = Field(
        default=None,
        description="Alternate alerts array"
    )
    total: Optional[int] = Field(
        default=None,
        description="Total alerts returned by the response"
    )

    class Config:
        extra = "allow"
