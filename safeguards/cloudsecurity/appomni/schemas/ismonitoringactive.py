"""Schema for ismonitoringactive transformation input."""

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class ServiceItem(BaseModel):
    """A single SaaS service entry."""

    enabled: Optional[bool] = Field(
        None,
        description="Whether the service is enabled.",
    )
    monitoring_enabled: Optional[bool] = Field(
        None,
        description="Whether monitoring is enabled for the service.",
    )

    class Config:
        extra = "allow"


class IsmonitoringactiveInput(BaseModel):
    """
    Expected input schema for the ismonitoringactive transformation.

    Criteria key: isMonitoringActive

    Evaluates that at least one SaaS service is connected and actively
    being monitored. The list of services may appear under 'results',
    'data', or 'items'.
    """

    results: Optional[List[ServiceItem]] = Field(
        None,
        description="List of services (primary key).",
    )
    data: Optional[List[ServiceItem]] = Field(
        None,
        description="List of services (alternate key).",
    )
    items: Optional[List[ServiceItem]] = Field(
        None,
        description="List of services (alternate key).",
    )

    class Config:
        extra = "allow"
