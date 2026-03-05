"""Schema for isurlrewriteenabled transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class URLProtectionSettings(BaseModel):
    """URL/link protection settings."""

    enabled: Optional[bool] = None

    class Config:
        extra = "allow"


class RemediationActions(BaseModel):
    """Remediation action configuration."""

    actions: Optional[List[Dict[str, Any]]] = None

    class Config:
        extra = "allow"


class Threat(BaseModel):
    """Single threat entry from Abnormal Security."""

    attackVector: Optional[str] = None
    threatType: Optional[str] = None

    class Config:
        extra = "allow"


class IsurlrewriteenabledInput(BaseModel):
    """
    Expected input schema for the isurlrewriteenabled transformation.
    Criteria key: isURLRewriteEnabled

    Checks URL protection settings, remediation actions, and URL-based
    threat detections from Abnormal Security.
    """

    settings: Optional[Dict[str, Any]] = None
    urlProtection: Optional[URLProtectionSettings] = None
    linkProtection: Optional[URLProtectionSettings] = None
    remediationActions: Optional[RemediationActions] = None
    remediation: Optional[RemediationActions] = None
    threats: Optional[List[Threat]] = None
    results: Optional[List[Threat]] = None

    class Config:
        extra = "allow"
