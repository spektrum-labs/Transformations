"""Schema for isremovablemediacontrolled transformation input."""
from typing import Any, Dict, List, Optional, Union

from pydantic import BaseModel, Field


class ScanSettings(BaseModel):
    """Scan settings within a policy."""
    scan_removable_media: Optional[Union[bool, str]] = Field(None, description="Scan removable media on insert")
    scanRemovableMedia: Optional[Union[bool, str]] = Field(None, description="Alternate removable media scan field")

    class Config:
        extra = "allow"


class PolicyItem(BaseModel):
    """A single policy from the ThreatDown Nebula API."""
    name: Optional[str] = Field(None, description="Policy name")
    policyName: Optional[str] = Field(None, description="Alternate policy name field")
    removable_media: Optional[Union[bool, str, Dict]] = Field(None, description="Removable media control settings")
    removableMedia: Optional[Union[bool, str, Dict]] = Field(None, description="Alternate removable media field")
    usb_scan: Optional[Union[bool, str, Dict]] = Field(None, description="USB scanning settings")
    usbScan: Optional[Union[bool, str, Dict]] = Field(None, description="Alternate USB scan field")
    scan_removable_media: Optional[Union[bool, str]] = Field(None, description="Scan removable media on insert")
    device_control: Optional[Union[bool, str, Dict]] = Field(None, description="Device control settings")
    deviceControl: Optional[Union[bool, str, Dict]] = Field(None, description="Alternate device control field")
    scan_settings: Optional[ScanSettings] = Field(None, description="Scan configuration settings")
    scanSettings: Optional[ScanSettings] = Field(None, description="Alternate scan settings field")

    class Config:
        extra = "allow"


class IsremovablemediacontrolledInput(BaseModel):
    """Expected input schema for the isremovablemediacontrolled transformation.
    Criteria key: isRemovableMediaControlled
    Source: ThreatDown Nebula /nebula/v1/policies endpoint."""
    policies: Optional[List[PolicyItem]] = Field(None, description="List of policies")
    data: Optional[Any] = Field(None, description="Alternate key for nested data")
    results: Optional[List[PolicyItem]] = Field(None, description="Alternate key for policies list")

    class Config:
        extra = "allow"
