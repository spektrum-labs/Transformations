"""Schema for ismfaenabledforidentityprovider transformation input."""
from typing import Any, Dict, List, Optional, Union

from pydantic import BaseModel, Field


class IdentityProviderRecord(BaseModel):
    """Individual identity provider object from Britive /api/v1/identity-providers."""
    id: Optional[str] = Field(None, description="Identity provider identifier")
    name: Optional[str] = Field(None, description="Identity provider name")
    type: Optional[str] = Field(None, description="Identity provider type")
    mfaEnabled: Optional[Union[bool, str]] = Field(None, description="Whether MFA is enabled")
    scimEnabled: Optional[bool] = Field(None, description="Whether SCIM provisioning is enabled")
    ssoProvider: Optional[str] = Field(None, description="SSO provider name")
    scimProvider: Optional[str] = Field(None, description="SCIM provider name")

    class Config:
        extra = "allow"


class IsmfaenabledforidentityproviderInput(BaseModel):
    """Expected input schema for the ismfaenabledforidentityprovider transformation. Criteria key: isMFAEnabledForIdentityProvider"""
    data: Optional[List[IdentityProviderRecord]] = Field(None, description="List of identity provider objects")
    identityProviders: Optional[List[IdentityProviderRecord]] = Field(None, description="Alternate list of identity provider objects")

    class Config:
        extra = "allow"
