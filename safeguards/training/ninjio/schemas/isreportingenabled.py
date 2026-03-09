"""Schema for isreportingenabled transformation input."""
from typing import Any, Dict, List, Optional, Union

from pydantic import BaseModel, Field


class ReportingCampaignItem(BaseModel):
    """A single campaign with potential ALERT/reporter configuration."""
    status: Optional[str] = Field(None, description="Campaign status (e.g. active, scheduled, running)")
    state: Optional[str] = Field(None, description="Alternate status field")
    alert_enabled: Optional[Union[bool, str]] = Field(None, description="Whether ALERT is enabled")
    alertEnabled: Optional[Union[bool, str]] = Field(None, description="Alternate ALERT enabled field (camelCase)")
    reporter_enabled: Optional[Union[bool, str]] = Field(None, description="Whether reporter is enabled")
    reporterEnabled: Optional[Union[bool, str]] = Field(None, description="Alternate reporter enabled field (camelCase)")
    phish_alert: Optional[Union[bool, str]] = Field(None, description="Whether phish alert is configured")
    phishAlert: Optional[Union[bool, str]] = Field(None, description="Alternate phish alert field (camelCase)")
    alert_configured: Optional[Union[bool, str]] = Field(None, description="Whether alert is configured")
    alertConfigured: Optional[Union[bool, str]] = Field(None, description="Alternate alert configured field (camelCase)")

    class Config:
        extra = "allow"


class IsreportingenabledInput(BaseModel):
    """Expected input schema for the isreportingenabled transformation. Criteria key: isReportingEnabled"""
    results: Optional[List[ReportingCampaignItem]] = Field(None, description="List of campaigns")
    data: Optional[Any] = Field(None, description="Alternate key for campaigns list or nested data")
    campaigns: Optional[List[ReportingCampaignItem]] = Field(None, description="Alternate key for campaigns list")
    items: Optional[List[ReportingCampaignItem]] = Field(None, description="Alternate key for campaigns list")

    class Config:
        extra = "allow"
