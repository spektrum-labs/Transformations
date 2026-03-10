"""Schema for ispatchmanagementenabled transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class DeviceConfiguration(BaseModel):
    """Intune device configuration profile for update management."""

    id: Optional[str] = None
    displayName: Optional[str] = None

    class Config:
        extra = "allow"


class IspatchmanagementenabledInput(BaseModel):
    """
    Expected input schema for the ispatchmanagementenabled transformation.
    Criteria key: isPatchManagementEnabled

    Checks for Windows Update for Business (WUfB) update ring configuration
    profiles by inspecting @odata.type for 'windowsUpdateForBusinessConfiguration'
    and display names for update-related keywords.
    """

    value: Optional[List[DeviceConfiguration]] = None
    configurations: Optional[List[DeviceConfiguration]] = None

    class Config:
        extra = "allow"
