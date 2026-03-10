"""Schema for isosversioncurrent transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ManagedDevice(BaseModel):
    """Intune managed device with OS version info."""

    id: Optional[str] = None
    deviceName: Optional[str] = None
    operatingSystem: Optional[str] = None
    osVersion: Optional[str] = None

    class Config:
        extra = "allow"


class IsosversioncurrentInput(BaseModel):
    """
    Expected input schema for the isosversioncurrent transformation.
    Criteria key: isOSVersionCurrent

    Uses a relative approach: finds the highest major version per OS family
    across all devices, then checks if devices are within 2 major versions
    of the highest observed version. Returns true if >= 80% are current.
    """

    value: Optional[List[ManagedDevice]] = None
    devices: Optional[List[ManagedDevice]] = None

    class Config:
        extra = "allow"
