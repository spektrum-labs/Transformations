"""Schema for ispatchmanagementvalid transformation input."""
from typing import Any, Dict, Optional

from pydantic import BaseModel, Field


class HealthPolicy(BaseModel):
    """Nested health policy object."""
    status: Optional[str] = Field(None, description="Health policy status")
    health_status: Optional[str] = Field(None, description="Current health status")

    class Config:
        extra = "allow"


class IspatchmanagementvalidInput(BaseModel):
    """Expected input schema for the ispatchmanagementvalid transformation.
    Criteria key: isPatchManagementValid
    Source: ManageEngine Endpoint Central GET /api/1.4/patch/summary + GET /api/1.4/patch/healthpolicy"""
    total_patches: Optional[int] = Field(None, description="Total patches tracked")
    totalPatches: Optional[int] = Field(None, description="Alternate total patches field")
    installed_patches: Optional[int] = Field(None, description="Installed patches count")
    installedPatches: Optional[int] = Field(None, description="Alternate installed field")
    missing_patches: Optional[int] = Field(None, description="Missing patches count")
    missingPatches: Optional[int] = Field(None, description="Alternate missing field")
    healthy_systems: Optional[int] = Field(None, description="Healthy systems count")
    healthySystems: Optional[int] = Field(None, description="Alternate healthy systems field")
    vulnerable_systems: Optional[int] = Field(None, description="Vulnerable systems count")
    vulnerableSystems: Optional[int] = Field(None, description="Alternate vulnerable field")
    total_systems: Optional[int] = Field(None, description="Total systems scanned")
    totalSystems: Optional[int] = Field(None, description="Alternate total systems field")
    health_policy: Optional[HealthPolicy] = Field(None, description="Health policy data")
    healthPolicy: Optional[HealthPolicy] = Field(None, description="Alternate health policy field")
    health_status: Optional[str] = Field(None, description="Overall health status")
    healthStatus: Optional[str] = Field(None, description="Alternate health status field")

    class Config:
        extra = "allow"
