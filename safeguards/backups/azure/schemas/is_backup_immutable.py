"""Schema for is_backup_immutable transformation input."""

from typing import Optional
from pydantic import BaseModel, Field


class ImmutabilitySettings(BaseModel):
    """Immutability settings for an Azure Recovery Services Vault."""
    state: Optional[str] = Field(
        default=None,
        description="Immutability state (e.g., Locked, Unlocked, NotConfigured)"
    )

    class Config:
        extra = "allow"


class IsBackupImmutableProperties(BaseModel):
    """Properties containing immutability settings."""
    immutabilitySettings: Optional[ImmutabilitySettings] = Field(
        default=None,
        description="Immutability settings for the vault"
    )

    class Config:
        extra = "allow"


class IsBackupImmutableInput(BaseModel):
    """Expected input schema for the is_backup_immutable transformation. Criteria key: isBackupImmutable"""
    properties: Optional[IsBackupImmutableProperties] = Field(
        default=None,
        description="Properties containing immutability settings for the vault"
    )

    class Config:
        extra = "allow"
