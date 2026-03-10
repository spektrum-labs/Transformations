"""Schema for isbackupencrypted transformation input."""

from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, Field


class EncryptionConfig(BaseModel):
    """Nested encryption configuration object."""
    encrypt: Optional[Union[bool, str]] = None
    enabled: Optional[Union[bool, str]] = None
    cipherType: Optional[str] = None
    cipher: Optional[str] = None

    class Config:
        extra = "allow"


class StoragePolicyCopy(BaseModel):
    """Copy-level properties within a storage pool."""
    copyEncryption: Optional[Union[str, bool]] = None
    encryptData: Optional[Union[str, bool]] = None
    encryptionType: Optional[Union[str, bool]] = None

    class Config:
        extra = "allow"


class StoragePool(BaseModel):
    """Single storage pool/policy entry for encryption evaluation."""
    encryption: Optional[Union[str, bool, EncryptionConfig]] = None
    encryptionType: Optional[Union[str, bool]] = None
    encryptData: Optional[Union[str, bool]] = None
    copyInfo: Optional[List[StoragePolicyCopy]] = None
    storagePolicyCopies: Optional[List[StoragePolicyCopy]] = None

    class Config:
        extra = "allow"


class IsbackupencryptedInput(BaseModel):
    """
    Expected input schema for the isbackupencrypted transformation.
    Criteria key: isBackupEncrypted
    """
    storagePoolList: Optional[List[StoragePool]] = None
    storagePool: Optional[List[StoragePool]] = None
    storagePolicies: Optional[List[StoragePool]] = None
    policies: Optional[List[StoragePool]] = None

    class Config:
        extra = "allow"
