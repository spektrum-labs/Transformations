"""Schema for isbehavioralmonitoringvalid transformation input."""
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class VulnerabilityItem(BaseModel):
    """A vulnerability entry from the threats API."""
    severity: Optional[str] = Field(None, description="Vulnerability severity (critical, high, medium, low)")
    risk_level: Optional[str] = Field(None, description="Alternate severity field")
    riskLevel: Optional[str] = Field(None, description="Alternate risk level field")
    cve_id: Optional[str] = Field(None, description="CVE identifier")
    title: Optional[str] = Field(None, description="Vulnerability title")

    class Config:
        extra = "allow"


class IsbehavioralmonitoringvalidInput(BaseModel):
    """Expected input schema for the isbehavioralmonitoringvalid transformation.
    Criteria key: isBehavioralMonitoringValid
    Source: ManageEngine Endpoint Central GET /dcapi/threats/vulnerabilities"""
    vulnerabilities: Optional[List[VulnerabilityItem]] = Field(None, description="List of vulnerabilities")
    vulnerability_details: Optional[List[VulnerabilityItem]] = Field(None, description="Alternate vulnerabilities field")
    vulnerabilityDetails: Optional[List[VulnerabilityItem]] = Field(None, description="Alternate field")
    data: Optional[Any] = Field(None, description="Alternate data key")
    total_vulnerabilities: Optional[int] = Field(None, description="Total vulnerability count")
    totalVulnerabilities: Optional[int] = Field(None, description="Alternate total field")
    critical: Optional[int] = Field(None, description="Critical vulnerability count")
    critical_count: Optional[int] = Field(None, description="Alternate critical count field")
    high: Optional[int] = Field(None, description="High vulnerability count")
    high_count: Optional[int] = Field(None, description="Alternate high count field")
    scan_status: Optional[str] = Field(None, description="Vulnerability scan status")
    scanStatus: Optional[str] = Field(None, description="Alternate scan status field")
    last_scan_time: Optional[str] = Field(None, description="Last vulnerability scan timestamp")
    lastScanTime: Optional[str] = Field(None, description="Alternate last scan field")

    class Config:
        extra = "allow"
