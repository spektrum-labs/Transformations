"""Schema for isSSOEnabled transformation input."""
from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, Field


class IsSSOEnabledInput(BaseModel):
    """Expected input shape for the isSSOEnabled transformation.

    Maps to the SentinelOne /web/api/v2.1/sso API response.
    The returnSpec extracts the top-level 'data' key, which is a dict
    containing SSO/SAML configuration fields.
    """

    # Primary enablement flag — present when SSO has been explicitly toggled
    enabled: Optional[bool] = Field(None, description="Whether SSO/SAML is currently enabled")
    isEnabled: Optional[bool] = Field(None, description="Alternative enablement flag used by some console versions")

    # IdP configuration fields
    idpSSOUrl: Optional[str] = Field(None, description="Identity Provider SSO redirect URL")
    idpMetadataUrl: Optional[str] = Field(None, description="Identity Provider metadata URL")
    idpUrl: Optional[str] = Field(None, description="Generic IdP URL (alternate field name)")
    metadataUrl: Optional[str] = Field(None, description="SP or IdP metadata URL")
    idpCertificate: Optional[str] = Field(None, description="PEM-encoded IdP X.509 signing certificate")

    # Service Provider fields
    spEntityId: Optional[str] = Field(None, description="Service Provider entity ID for SAML assertions")
    spAcsUrl: Optional[str] = Field(None, description="Assertion Consumer Service URL")

    # Misc
    defaultUserRole: Optional[str] = Field(None, description="Default role assigned to SSO-authenticated users")
    emailAttrName: Optional[str] = Field(None, description="SAML attribute name carrying the user email")

    class Config:
        extra = "allow"
