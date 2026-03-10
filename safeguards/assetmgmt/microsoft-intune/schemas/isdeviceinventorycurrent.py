"""Schema for isdeviceinventorycurrent transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ManagedDevice(BaseModel):
    """Intune managed device with sync timestamp."""

    id: Optional[str] = None
    deviceName: Optional[str] = None
    lastSyncDateTime: Optional[str] = None
    operatingSystem: Optional[str] = None

    class Config:
        extra = "allow"


class IsdeviceinventorycurrentInput(BaseModel):
    """
    Expected input schema for the isdeviceinventorycurrent transformation.
    Criteria key: isDeviceInventoryCurrent

    Evaluates lastSyncDateTime for each managed device. Returns true
    if >= 80% of devices have synced within the last 30 days.
    """

    value: Optional[List[ManagedDevice]] = None
    devices: Optional[List[ManagedDevice]] = None

    class Config:
        extra = "allow"
