"""Schema for isSSOEnabled transformation input."""
from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, Field


class SSOSettingsData(BaseModel):
    """SSO configuration object returned by /sso endpoint."""
    isSsoEnabled: Optional[bool] = Field(None, description="Whether SSO is enabled")
    ssoEnabled: Optional[bool] = Field(None, description="Alternative SSO enabled flag")
    samlEnabled: Optional[bool] = Field(None, description="Whether SAML is enabled")
    enabled: Optional[bool] = Field(None, description="Generic enabled flag")
    isEnabled: Optional[bool] = Field(None, description="Generic isEnabled flag")
    entityId: Optional[str] = Field(None, description="SAML entity ID")
    loginUrl: Optional[str] = Field(None, description="SAML identity provider login URL")
    logoutUrl: Optional[str] = Field(None, description="SAML logout URL")
    certificate: Optional[str] = Field(None, description="SAML certificate")
    issuer: Optional[str] = Field(None, description="SAML issuer")

    class Config:
        extra = "allow"


class IsSSOEnabledInput(BaseModel):
    """Expected input shape for the isSSOEnabled transformation."""
    data: Optional[Union[SSOSettingsData, Dict[str, Any], List[Any]]] = Field(None, description="SSO settings object or list")
    getSSOSettings: Optional[Dict[str, Any]] = Field(None, description="Merged method result from getSSOSettings")

    class Config:
        extra = "allow"
