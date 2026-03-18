"""Schema for isremovablemediacontrolled transformation input."""
from typing import Any, Dict, List, Optional, Union

from pydantic import BaseModel, Field


class DeviceItem(BaseModel):
    """A device entry from the Device Control Manager report."""
    status: Optional[str] = Field(None, description="Device status (blocked, monitored, allowed)")
    device_status: Optional[str] = Field(None, description="Alternate status field")
    action: Optional[str] = Field(None, description="Action taken (block, audit, allow)")
    device_type: Optional[str] = Field(None, description="Device type (USB, CD/DVD, etc.)")
    deviceType: Optional[str] = Field(None, description="Alternate device type field")

    class Config:
        extra = "allow"


class IsremovablemediacontrolledInput(BaseModel):
    """Expected input schema for the isremovablemediacontrolled transformation.
    Criteria key: isRemovableMediaControlled
    Source: ManageEngine Endpoint Central GET /api/1.4/reports/dcm/devicesummary"""
    devices: Optional[List[DeviceItem]] = Field(None, description="List of device entries")
    device_summary: Optional[List[DeviceItem]] = Field(None, description="Device summary list")
    deviceSummary: Optional[List[DeviceItem]] = Field(None, description="Alternate summary field")
    data: Optional[Any] = Field(None, description="Alternate data key")
    total_devices: Optional[int] = Field(None, description="Total devices tracked")
    totalDevices: Optional[int] = Field(None, description="Alternate total field")
    blocked_devices: Optional[int] = Field(None, description="Blocked device count")
    blockedDevices: Optional[int] = Field(None, description="Alternate blocked field")
    monitored_devices: Optional[int] = Field(None, description="Monitored device count")
    monitoredDevices: Optional[int] = Field(None, description="Alternate monitored field")
    dcm_enabled: Optional[Union[bool, str]] = Field(None, description="Device control module enabled")
    deviceControlEnabled: Optional[Union[bool, str]] = Field(None, description="Alternate DCM enabled field")

    class Config:
        extra = "allow"
