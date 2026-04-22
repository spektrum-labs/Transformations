from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, Field


class OrgSecurityModel(BaseModel):
    authType: Optional[str] = Field(None, description="Authentication type, e.g. LOCAL, RADIUS, SSO, SAML")
    authenticationMethod: Optional[str] = Field(None, description="Authentication method as an alternate field name")
    ssoEnabled: Optional[Any] = Field(None, description="Boolean or string flag indicating SSO is enabled")
    samlEnabled: Optional[Any] = Field(None, description="Boolean or string flag indicating SAML is enabled")

    class Config:
        extra = "allow"


class IsSAMLEnforcedInput(BaseModel):
    orgSecurity: Optional[OrgSecurityModel] = Field(None, description="Organization security settings from getOrgSecurity endpoint")
    authType: Optional[str] = Field(None, description="Top-level authType when orgSecurity is unwrapped")
    authenticationMethod: Optional[str] = Field(None, description="Top-level authenticationMethod when orgSecurity is unwrapped")
    ssoEnabled: Optional[Any] = Field(None, description="Top-level ssoEnabled flag when orgSecurity is unwrapped")
    samlEnabled: Optional[Any] = Field(None, description="Top-level samlEnabled flag when orgSecurity is unwrapped")

    class Config:
        extra = "allow"
