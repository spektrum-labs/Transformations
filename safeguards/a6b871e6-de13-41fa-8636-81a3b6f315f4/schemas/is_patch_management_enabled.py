"""Schema for is_patch_management_enabled transformation input."""

from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, Field


class Detection(BaseModel):
    """Single VM detection record."""
    QID: Optional[str] = Field(default=None, description="Qualys ID for the vulnerability")
    TYPE: Optional[str] = Field(default=None, description="Detection type (e.g. Confirmed, Potential)")
    SEVERITY: Optional[str] = Field(default=None, description="Severity level (1-5)")
    STATUS: Optional[str] = Field(default=None, description="Detection status (New, Active, Fixed, Re-Opened)")
    IS_PATCHABLE: Optional[str] = Field(default=None, description="Whether a patch exists (0 or 1)")
    FIRST_FOUND_DATETIME: Optional[str] = Field(default=None, description="When the detection was first found")
    LAST_UPDATE_DATETIME: Optional[str] = Field(default=None, description="When the detection was last updated")

    class Config:
        extra = "allow"


class DetectionList(BaseModel):
    """Container for detection records on a host."""
    DETECTION: Optional[Union[Detection, List[Detection]]] = Field(
        default=None, description="Detection record(s) for the host"
    )

    class Config:
        extra = "allow"


class Host(BaseModel):
    """Single host record with detections."""
    ID: Optional[str] = Field(default=None, description="Qualys host ID")
    IP: Optional[str] = Field(default=None, description="IP address of the host")
    DNS: Optional[str] = Field(default=None, description="DNS hostname")
    OS: Optional[str] = Field(default=None, description="Operating system")
    DETECTION_LIST: Optional[DetectionList] = Field(
        default=None, description="List of detections on this host"
    )

    class Config:
        extra = "allow"


class HostList(BaseModel):
    """Container for host records. Absent when no results are returned."""
    HOST: Optional[Union[Host, List[Host]]] = Field(
        default=None, description="Host record(s) with patchable detections"
    )

    class Config:
        extra = "allow"


class Response(BaseModel):
    """RESPONSE node from the Qualys Host List VM Detection API."""
    DATETIME: Optional[str] = Field(default=None, description="Response timestamp from Qualys")
    HOST_LIST: Optional[HostList] = Field(
        default=None,
        description="List of hosts with detections. Absent when no patchable detections exist."
    )

    class Config:
        extra = "allow"


class HostListVmDetectionOutput(BaseModel):
    """Top-level Qualys Host List VM Detection API response."""
    RESPONSE: Optional[Response] = Field(default=None, description="API response payload")

    class Config:
        extra = "allow"


class IsPatchManagementEnabledInput(BaseModel):
    """
    Expected input schema for the is_patch_management_enabled transformation.

    This schema validates the Qualys Host List VM Detection API response
    filtered by is_patchable=1. The presence of HOST_LIST with HOST entries
    indicates that patch management is enabled.
    """
    HOST_LIST_VM_DETECTION_OUTPUT: Optional[HostListVmDetectionOutput] = Field(
        default=None,
        description="Qualys Host List VM Detection API response"
    )

    class Config:
        extra = "allow"
