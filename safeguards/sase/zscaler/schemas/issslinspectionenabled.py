"""Schema for issslinspectionenabled transformation input."""

from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, Field


class NamedReference(BaseModel):
    """Reference to a named Zscaler object (location, label, user, etc.)."""

    id: Optional[int] = None
    name: Optional[str] = None

    class Config:
        extra = "allow"


class DoNotDecryptSubActions(BaseModel):
    """Sub-actions for DO_NOT_DECRYPT SSL rules."""

    bypassOtherPolicies: Optional[bool] = None
    serverCertificates: Optional[str] = None
    ocspCheck: Optional[bool] = None
    minTLSVersion: Optional[str] = None
    blockSslTrafficWithNoSniEnabled: Optional[bool] = None

    class Config:
        extra = "allow"


class DecryptSubActions(BaseModel):
    """Sub-actions for DECRYPT SSL rules."""

    serverCertificates: Optional[str] = None
    ocspCheck: Optional[bool] = None
    minClientTLSVersion: Optional[str] = None
    minServerTLSVersion: Optional[str] = None
    blockUndecrypt: Optional[bool] = None
    http2Enabled: Optional[bool] = None
    blockSslTrafficWithNoSniEnabled: Optional[bool] = None

    class Config:
        extra = "allow"


class SSLAction(BaseModel):
    """Action configuration for an SSL inspection rule."""

    type: Optional[str] = Field(None, description="DECRYPT or DO_NOT_DECRYPT")
    doNotDecryptSubActions: Optional[DoNotDecryptSubActions] = None
    decryptSubActions: Optional[DecryptSubActions] = None
    showEUN: Optional[bool] = None
    showEUNATP: Optional[bool] = None
    overrideDefaultCertificate: Optional[bool] = None

    class Config:
        extra = "allow"


class SSLInspectionRule(BaseModel):
    """Single SSL inspection rule from Zscaler ZIA."""

    id: Optional[int] = None
    accessControl: Optional[str] = None
    name: Optional[str] = None
    order: Optional[int] = None
    rank: Optional[int] = None
    roadWarriorForKerberos: Optional[bool] = None
    urlCategories: Optional[List[str]] = None
    cloudApplications: Optional[List[str]] = None
    action: Optional[SSLAction] = None
    state: Optional[str] = Field(None, description="ENABLED or DISABLED")
    description: Optional[str] = None
    lastModifiedTime: Optional[int] = None
    lastModifiedBy: Optional[NamedReference] = None
    locations: Optional[List[NamedReference]] = None
    locationGroups: Optional[List[NamedReference]] = None
    labels: Optional[List[NamedReference]] = None
    sourceIpGroups: Optional[List[NamedReference]] = None
    predefined: Optional[bool] = None
    defaultRule: Optional[bool] = None

    class Config:
        extra = "allow"


class SSLInspectionSettings(BaseModel):
    """SSL inspection settings (alternative dict format) from Zscaler ZIA."""

    sslInterceptionEnabled: Optional[bool] = None
    enabled: Optional[bool] = None
    sslDecryptionEnabled: Optional[bool] = None
    certificates: Optional[List[Dict[str, Any]]] = None
    rootCertificate: Optional[Dict[str, Any]] = None

    class Config:
        extra = "allow"


class IssslinspectionenabledInput(BaseModel):
    """
    Expected input schema for the issslinspectionenabled transformation.
    Criteria key: isSSLInspectionEnabled

    Checks for SSL/TLS inspection settings and rules in Zscaler ZIA.
    The sslInspectionRules field may be a dict (single config) or
    a list (multiple rules). The API returns an array of SSL inspection
    rules with action types DECRYPT or DO_NOT_DECRYPT.
    """

    sslInspectionRules: Optional[Union[SSLInspectionSettings, List[SSLInspectionRule]]] = None
    responseData: Optional[Union[Dict[str, Any], List[SSLInspectionRule]]] = None
    sslScanEnabled: Optional[bool] = None
    sslInterception: Optional[bool] = None

    class Config:
        extra = "allow"
