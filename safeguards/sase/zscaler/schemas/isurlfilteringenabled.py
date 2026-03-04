"""Schema for isurlfilteringenabled transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class NamedReference(BaseModel):
    """Reference to a named Zscaler object (location, label, user, etc.)."""

    id: Optional[int] = None
    name: Optional[str] = None

    class Config:
        extra = "allow"


class CbiProfile(BaseModel):
    """Cloud Browser Isolation profile."""

    profileSeq: Optional[int] = None
    id: Optional[str] = None
    name: Optional[str] = None
    url: Optional[str] = None

    class Config:
        extra = "allow"


class URLFilteringRule(BaseModel):
    """Single URL filtering rule from Zscaler ZIA."""

    id: Optional[int] = None
    accessControl: Optional[str] = None
    name: Optional[str] = None
    order: Optional[int] = None
    protocols: Optional[List[str]] = None
    departments: Optional[List[NamedReference]] = None
    users: Optional[List[NamedReference]] = None
    groups: Optional[List[NamedReference]] = None
    urlCategories: Optional[List[str]] = None
    excludeSrcCountries: Optional[bool] = None
    state: Optional[str] = Field(None, description="ENABLED or DISABLED")
    rank: Optional[int] = None
    requestMethods: Optional[List[str]] = None
    endUserNotificationUrl: Optional[str] = None
    blockOverride: Optional[bool] = None
    description: Optional[str] = None
    locations: Optional[List[NamedReference]] = None
    locationGroups: Optional[List[NamedReference]] = None
    labels: Optional[List[NamedReference]] = None
    lastModifiedTime: Optional[int] = None
    lastModifiedBy: Optional[NamedReference] = None
    enforceTimeValidity: Optional[bool] = None
    userAgentTypes: Optional[List[str]] = None
    deviceGroups: Optional[List[NamedReference]] = None
    deviceTrustLevels: Optional[List[str]] = None
    cbiProfile: Optional[CbiProfile] = None
    cbiProfileId: Optional[int] = None
    capturePCAP: Optional[bool] = None
    sourceIpGroups: Optional[List[NamedReference]] = None
    browserEunTemplateId: Optional[int] = None
    httpHeaderProfiles: Optional[List[Any]] = None
    httpHeaderActionProfiles: Optional[List[Any]] = None
    usersAndGroupsSet: Optional[bool] = None
    groupsAndDepartmentsSet: Optional[bool] = None
    action: Optional[str] = Field(None, description="ALLOW, BLOCK, or ISOLATE")
    predefined: Optional[bool] = None
    enabled: Optional[bool] = None

    class Config:
        extra = "allow"


class IsurlfilteringenabledInput(BaseModel):
    """
    Expected input schema for the isurlfilteringenabled transformation.
    Criteria key: isURLFilteringEnabled

    Checks for URL filtering rules and URL categories configuration
    in Zscaler ZIA. The API returns an array of URL filtering rules
    with actions ALLOW, BLOCK, or ISOLATE.
    """

    urlFilteringRules: Optional[List[URLFilteringRule]] = None
    responseData: Optional[List[URLFilteringRule]] = None
    urlCategories: Optional[List[Dict[str, Any]]] = None

    class Config:
        extra = "allow"
