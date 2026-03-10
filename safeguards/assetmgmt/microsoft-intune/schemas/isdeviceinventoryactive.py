"""Schema for isdeviceinventoryactive transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ManagedDevice(BaseModel):
    """Intune managed device entry."""

    id: Optional[str] = None
    deviceName: Optional[str] = None
    operatingSystem: Optional[str] = None
    osVersion: Optional[str] = None
    managementAgent: Optional[str] = None

    class Config:
        extra = "allow"


class IsdeviceinventoryactiveInput(BaseModel):
    """
    Expected input schema for the isdeviceinventoryactive transformation.
    Criteria key: isDeviceInventoryActive

    Checks that at least one managed device exists in the Intune
    device inventory. Also extracts OS breakdown from operatingSystem field.
    """

    value: Optional[List[ManagedDevice]] = None
    devices: Optional[List[ManagedDevice]] = None

    class Config:
        extra = "allow"
