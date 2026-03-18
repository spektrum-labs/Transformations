"""Schema for ispatchmanagementenabled transformation input."""
from typing import Any, Dict, Optional

from pydantic import BaseModel, Field


class PatchSummary(BaseModel):
    """Nested patch summary object."""
    total: Optional[int] = Field(None, description="Total patches")
    installed: Optional[int] = Field(None, description="Installed patches")
    missing: Optional[int] = Field(None, description="Missing patches")

    class Config:
        extra = "allow"


class IspatchmanagementenabledInput(BaseModel):
    """Expected input schema for the ispatchmanagementenabled transformation.
    Criteria key: isPatchManagementEnabled
    Source: ManageEngine Endpoint Central GET /api/1.4/patch/summary"""
    total_patches: Optional[int] = Field(None, description="Total patches tracked")
    totalPatches: Optional[int] = Field(None, description="Alternate total patches field")
    installed_patches: Optional[int] = Field(None, description="Installed patches count")
    installedPatches: Optional[int] = Field(None, description="Alternate installed field")
    missing_patches: Optional[int] = Field(None, description="Missing patches count")
    missingPatches: Optional[int] = Field(None, description="Alternate missing field")
    systems_scanned: Optional[int] = Field(None, description="Systems scanned count")
    systemsScanned: Optional[int] = Field(None, description="Alternate systems scanned field")
    healthy_systems: Optional[int] = Field(None, description="Healthy systems count")
    healthySystems: Optional[int] = Field(None, description="Alternate healthy systems field")
    vulnerable_systems: Optional[int] = Field(None, description="Vulnerable systems count")
    vulnerableSystems: Optional[int] = Field(None, description="Alternate vulnerable field")
    patch_summary: Optional[PatchSummary] = Field(None, description="Nested patch summary")
    patchSummary: Optional[PatchSummary] = Field(None, description="Alternate summary field")
    db_update_status: Optional[str] = Field(None, description="Patch DB update status")
    last_scan_time: Optional[str] = Field(None, description="Last scan timestamp")

    class Config:
        extra = "allow"
