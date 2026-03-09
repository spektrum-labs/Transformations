"""Schema for islegacyauthblocked transformation input."""
from typing import Optional, Union

from pydantic import BaseModel, Field


class IslegacyauthblockedInput(BaseModel):
    """Expected input schema for the islegacyauthblocked transformation. Criteria key: isLegacyAuthBlocked"""

    rollRefreshTokenValues: Optional[Union[bool, str]] = Field(
        None, description="Whether OAuth refresh tokens rotate on use"
    )
    persistentGrantExpirationType: Optional[str] = Field(
        None, description="Expiration type for persistent grants (e.g. INDEFINITE_EXPIRY)"
    )

    class Config:
        extra = "allow"
