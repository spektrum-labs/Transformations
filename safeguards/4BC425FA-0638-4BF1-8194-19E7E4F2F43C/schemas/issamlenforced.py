"""Schema for issamlenforced transformation input."""

from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, Field


class SAMLProvider(BaseModel):
    """Single SAML provider record."""
    Arn: Optional[str] = None
    ValidUntil: Optional[str] = None
    CreateDate: Optional[str] = None

    class Config:
        extra = "allow"


class SAMLProviderList(BaseModel):
    """Container for SAML provider records."""
    member: Optional[Union[SAMLProvider, List[SAMLProvider]]] = None

    class Config:
        extra = "allow"


class ListSAMLProvidersResult(BaseModel):
    """Result from IAM ListSAMLProviders API."""
    SAMLProviderList: Optional[SAMLProviderList] = None

    class Config:
        extra = "allow"


class ListSAMLProvidersResponse(BaseModel):
    """AWS IAM ListSAMLProviders response."""
    ListSAMLProvidersResult: Optional[ListSAMLProvidersResult] = None
    ResponseMetadata: Optional[Dict[str, Any]] = None

    class Config:
        extra = "allow"


class ApiResponse(BaseModel):
    """Wrapper for the API response."""
    ListSAMLProvidersResponse: Optional[ListSAMLProvidersResponse] = None

    class Config:
        extra = "allow"


class IsSAMLEnforcedInput(BaseModel):
    """
    Expected input schema for the issamlenforced transformation.

    This schema validates the IAM ListSAMLProviders API response that checks
    if SAML providers are configured for SSO authentication.
    """

    apiResponse: Optional[ApiResponse] = Field(
        default=None,
        description="IAM ListSAMLProviders response containing SAML provider list"
    )

    class Config:
        extra = "allow"
