"""Schema for isconfigurationmanaged transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ConfigurationProfile(BaseModel):
    """Intune device configuration profile."""

    id: Optional[str] = None
    displayName: Optional[str] = None

    class Config:
        extra = "allow"


class ManagedDevice(BaseModel):
    """Intune managed device with management agent info."""

    id: Optional[str] = None
    deviceName: Optional[str] = None
    operatingSystem: Optional[str] = None
    managementAgent: Optional[str] = None

    class Config:
        extra = "allow"


class IsconfigurationmanagedInput(BaseModel):
    """
    Expected input schema for the isconfigurationmanaged transformation.
    Criteria key: isConfigurationManaged

    Receives merged data from getDeviceConfigurations and getManagedDevices.
    Returns true if config profiles exist AND managed devices exist with
    an active MDM management agent (mdm, easMdm, configurationManagerClientMdm,
    configurationManagerClient).
    """

    value: Optional[List[Any]] = None
    configurations: Optional[List[ConfigurationProfile]] = None
    devices: Optional[List[ManagedDevice]] = None

    class Config:
        extra = "allow"
