"""Schema for isdeviceconfigured transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class DeviceConfiguration(BaseModel):
    """Intune device configuration profile entry."""

    id: Optional[str] = None
    displayName: Optional[str] = None

    class Config:
        extra = "allow"


class IsdeviceconfiguredInput(BaseModel):
    """
    Expected input schema for the isdeviceconfigured transformation.
    Criteria key: isDeviceConfigured

    Checks that at least one device configuration profile exists in Intune.
    Profiles include device restrictions, Wi-Fi, VPN, email, certificates,
    WUfB update rings, and custom OMA-URI profiles. Inspects @odata.type
    for profile type breakdown.
    """

    value: Optional[List[DeviceConfiguration]] = None
    configurations: Optional[List[DeviceConfiguration]] = None

    class Config:
        extra = "allow"
