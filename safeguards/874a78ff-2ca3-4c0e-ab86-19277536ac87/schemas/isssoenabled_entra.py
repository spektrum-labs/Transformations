"""Schema for isssoenabled_entra transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class GraphListBody(BaseModel):
    """A Microsoft Graph collection response: {"value": [...]}."""

    value: Optional[List[Dict[str, Any]]] = None

    class Config:
        extra = "allow"


class IsssoenabledEntraInput(BaseModel):
    """
    Expected input schema for the isssoenabled_entra transformation.
    Criteria key: isSSOEnabled

    servicePrincipals: GET /v1.0/servicePrincipals?$select=id,appId,displayName,
        preferredSingleSignOnMode,accountEnabled,appOwnerOrganizationId,servicePrincipalType
    domains: GET /v1.0/domains?$select=id,authenticationType,isVerified
    """

    servicePrincipals: Optional[GraphListBody] = None
    domains: Optional[GraphListBody] = None

    class Config:
        extra = "allow"
