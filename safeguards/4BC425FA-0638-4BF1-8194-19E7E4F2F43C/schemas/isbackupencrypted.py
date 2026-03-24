"""Schema for isbackupencrypted transformation input."""
from typing import Any, Dict, Optional
from pydantic import BaseModel, Field


class EncryptionConfig(BaseModel):
    """Encryption configuration for an Azure Recovery Services Vault."""
    keyVaultProperties: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Key Vault properties if customer-managed key encryption is configured"
    )
    infrastructureEncryption: Optional[str] = Field(
        default=None,
        description="Infrastructure encryption state (e.g., Enabled, Disabled)"
    )

    class Config:
        extra = "allow"


class IsBackupEncryptedProperties(BaseModel):
    """Properties containing encryption configuration."""
    encryption: Optional[EncryptionConfig] = Field(
        default=None,
        description="Encryption configuration for the vault"
    )

    class Config:
        extra = "allow"


class IsbackupencryptedInput(BaseModel):
    """Expected input schema for the isbackupencrypted transformation. Criteria key: isBackupEncrypted"""
    properties: Optional[IsBackupEncryptedProperties] = Field(
        default=None,
        description="Properties containing encryption configuration for the vault"
    )

    class Config:
        extra = "allow"
