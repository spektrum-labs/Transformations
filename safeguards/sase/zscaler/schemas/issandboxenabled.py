"""Schema for issandboxenabled transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class SandboxSettings(BaseModel):
    """Cloud sandbox settings from Zscaler ZIA."""

    sandboxEnabled: Optional[bool] = None
    cloudSandbox: Optional[bool] = None
    behavioralAnalysis: Optional[bool] = None
    behavioralAnalysisEnabled: Optional[bool] = None
    fileDetonation: Optional[bool] = None
    fileDetonationEnabled: Optional[bool] = None
    advancedSettings: Optional[Dict[str, Any]] = None
    analysisSettings: Optional[Dict[str, Any]] = None

    class Config:
        extra = "allow"


class IssandboxenabledInput(BaseModel):
    """
    Expected input schema for the issandboxenabled transformation.
    Criteria key: isSandboxEnabled

    Checks for cloud sandbox and behavioral analysis configuration
    in Zscaler ZIA.
    """

    sandboxSettings: Optional[SandboxSettings] = None
    responseData: Optional[Dict[str, Any]] = None

    class Config:
        extra = "allow"
