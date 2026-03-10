"""Schema for isthirdpartymonitoringenabled transformation input."""

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class ThirdPartyServiceItem(BaseModel):
    """A single connected service entry for third-party monitoring."""

    enabled: Optional[bool] = Field(
        None,
        description="Whether the service is enabled.",
    )
    third_party_apps_monitored: Optional[bool] = Field(
        None,
        description="Whether third-party OAuth apps are monitored (primary key).",
    )
    third_party_monitoring_enabled: Optional[bool] = Field(
        None,
        description="Whether third-party monitoring is enabled (alternate key).",
    )

    class Config:
        extra = "allow"


class IsthirdpartymonitoringenabledInput(BaseModel):
    """
    Expected input schema for the isthirdpartymonitoringenabled transformation.

    Criteria key: isThirdPartyMonitoringEnabled

    Evaluates that at least one connected service has third-party OAuth app
    monitoring enabled. The list of services may appear under 'results',
    'data', or 'items'.
    """

    results: Optional[List[ThirdPartyServiceItem]] = Field(
        None,
        description="List of services (primary key).",
    )
    data: Optional[List[ThirdPartyServiceItem]] = Field(
        None,
        description="List of services (alternate key).",
    )
    items: Optional[List[ThirdPartyServiceItem]] = Field(
        None,
        description="List of services (alternate key).",
    )

    class Config:
        extra = "allow"
