"""Schema for isransomwareprotectionenabled transformation input."""

from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, Field


class ThreatAnalysisConfiguration(BaseModel):
    """Nested threat analysis / anomaly configuration block."""
    threatScanEnabled: Optional[Union[bool, str]] = None
    isThreatScanEnabled: Optional[Union[bool, str]] = None
    anomalyDetectionEnabled: Optional[Union[bool, str]] = None
    isAnomalyDetectionEnabled: Optional[Union[bool, str]] = None
    ransomwareScanEnabled: Optional[Union[bool, str]] = None
    isRansomwareScanEnabled: Optional[Union[bool, str]] = None
    threatAnalysisEnabled: Optional[Union[bool, str]] = None
    scanEnabled: Optional[Union[bool, str]] = None

    class Config:
        extra = "allow"


class ThreatScanEvent(BaseModel):
    """Single threat scan or anomaly event entry."""

    class Config:
        extra = "allow"


class IsransomwareprotectionenabledInput(BaseModel):
    """
    Expected input schema for the isransomwareprotectionenabled transformation.
    Criteria key: isRansomwareProtectionEnabled
    """
    threatScanEnabled: Optional[Union[bool, str]] = None
    isThreatScanEnabled: Optional[Union[bool, str]] = None
    anomalyDetectionEnabled: Optional[Union[bool, str]] = None
    isAnomalyDetectionEnabled: Optional[Union[bool, str]] = None
    ransomwareScanEnabled: Optional[Union[bool, str]] = None
    isRansomwareScanEnabled: Optional[Union[bool, str]] = None
    threatAnalysisEnabled: Optional[Union[bool, str]] = None
    scanEnabled: Optional[Union[bool, str]] = None
    threatAnalysisConfiguration: Optional[ThreatAnalysisConfiguration] = None
    anomalyConfiguration: Optional[ThreatAnalysisConfiguration] = None
    configuration: Optional[ThreatAnalysisConfiguration] = None
    threatScanEvents: Optional[List[ThreatScanEvent]] = None
    anomalyEvents: Optional[List[ThreatScanEvent]] = None
    events: Optional[List[ThreatScanEvent]] = None

    class Config:
        extra = "allow"
