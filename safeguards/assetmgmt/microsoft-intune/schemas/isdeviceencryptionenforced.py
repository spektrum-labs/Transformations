"""Schema for isdeviceencryptionenforced transformation input."""

from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, Field


class CompliancePolicy(BaseModel):
    """Intune device compliance policy with encryption fields."""

    id: Optional[str] = None
    displayName: Optional[str] = None
    bitLockerEnabled: Optional[Union[bool, str]] = None
    storageRequireEncryption: Optional[Union[bool, str]] = None
    requireDeviceEncryption: Optional[Union[bool, str]] = None
    encryptionRequired: Optional[Union[bool, str]] = None
    storageRequireDeviceEncryption: Optional[Union[bool, str]] = None
    fileVaultEnabled: Optional[Union[bool, str]] = None

    class Config:
        extra = "allow"


class IsdeviceencryptionenforcedInput(BaseModel):
    """
    Expected input schema for the isdeviceencryptionenforced transformation.
    Criteria key: isDeviceEncryptionEnforced

    Checks compliance policies for device encryption requirements including
    BitLocker (Windows) and FileVault (macOS). Returns true if at least one
    policy requires device encryption.
    """

    value: Optional[List[CompliancePolicy]] = None
    policies: Optional[List[CompliancePolicy]] = None

    class Config:
        extra = "allow"
