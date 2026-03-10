"""Schema for issamlenforced transformation input."""

from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, Field


class IdentityProvider(BaseModel):
    """Single identity provider / SAML app entry."""
    type: Optional[str] = None
    identityServerType: Optional[str] = None
    enabled: Optional[Union[bool, str]] = None
    isEnabled: Optional[Union[bool, str]] = None

    class Config:
        extra = "allow"


class IssamlenforcedInput(BaseModel):
    """
    Expected input schema for the issamlenforced transformation.
    Criteria key: isSAMLEnforced
    """
    identityServerList: Optional[List[IdentityProvider]] = None
    samlAppList: Optional[List[IdentityProvider]] = None
    samlProviders: Optional[List[IdentityProvider]] = None
    identityProviders: Optional[List[IdentityProvider]] = None
    samlConfiguration: Optional[Dict[str, Any]] = None
    identityServerName: Optional[str] = None
    enabled: Optional[Union[bool, str]] = None
    isEnabled: Optional[Union[bool, str]] = None

    class Config:
        extra = "allow"
