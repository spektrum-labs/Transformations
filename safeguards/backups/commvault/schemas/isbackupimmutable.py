"""Schema for isbackupimmutable transformation input."""

from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, Field


class StoragePolicyCopy(BaseModel):
    """Copy-level properties with immutability fields."""
    wormStorageEnabled: Optional[Union[bool, str]] = None
    isWormEnabled: Optional[Union[bool, str]] = None
    complianceLock: Optional[Union[bool, str]] = None
    isComplianceLocked: Optional[Union[bool, str]] = None
    retentionLock: Optional[Union[bool, str]] = None
    isRetentionLocked: Optional[Union[bool, str]] = None
    isAirGapProtect: Optional[Union[bool, str]] = None
    airGapProtectEnabled: Optional[Union[bool, str]] = None
    immutabilityEnabled: Optional[Union[bool, str]] = None
    isImmutable: Optional[Union[bool, str]] = None
    objectLockEnabled: Optional[Union[bool, str]] = None

    class Config:
        extra = "allow"


class StoragePool(BaseModel):
    """Single storage pool entry for immutability evaluation."""
    wormStorageEnabled: Optional[Union[bool, str]] = None
    isWormEnabled: Optional[Union[bool, str]] = None
    complianceLock: Optional[Union[bool, str]] = None
    isComplianceLocked: Optional[Union[bool, str]] = None
    retentionLock: Optional[Union[bool, str]] = None
    isRetentionLocked: Optional[Union[bool, str]] = None
    isAirGapProtect: Optional[Union[bool, str]] = None
    airGapProtectEnabled: Optional[Union[bool, str]] = None
    immutabilityEnabled: Optional[Union[bool, str]] = None
    isImmutable: Optional[Union[bool, str]] = None
    objectLockEnabled: Optional[Union[bool, str]] = None
    copyInfo: Optional[List[StoragePolicyCopy]] = None
    storagePolicyCopies: Optional[List[StoragePolicyCopy]] = None

    class Config:
        extra = "allow"


class IsbackupimmutableInput(BaseModel):
    """
    Expected input schema for the isbackupimmutable transformation.
    Criteria key: isBackupImmutable
    """
    storagePoolList: Optional[List[StoragePool]] = None
    storagePool: Optional[List[StoragePool]] = None
    storagePolicies: Optional[List[StoragePool]] = None

    class Config:
        extra = "allow"
