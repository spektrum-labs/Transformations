"""Schema for issamlenforced transformation input."""
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class SAMLConfigRecord(BaseModel):
    """Individual SAML configuration object from Britive /api/saml/settings."""
    id: Optional[int] = Field(None, description="SAML config identifier")
    issuer: Optional[str] = Field(None, description="SAML issuer URL")
    x509CertExpirationDate: Optional[str] = Field(None, description="Certificate expiration date")
    signInUrl: Optional[str] = Field(None, description="SAML sign-in URL")
    signOutUrl: Optional[str] = Field(None, description="SAML sign-out URL")

    class Config:
        extra = "allow"


class IssamlenforcedInput(BaseModel):
    """Expected input schema for the issamlenforced transformation. Criteria key: isSAMLEnforced"""
    data: Optional[List[SAMLConfigRecord]] = Field(None, description="List of SAML config objects")
    value: Optional[List[SAMLConfigRecord]] = Field(None, description="Alternate list of SAML config objects")

    class Config:
        extra = "allow"
