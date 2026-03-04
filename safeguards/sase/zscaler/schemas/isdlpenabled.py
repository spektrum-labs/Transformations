"""Schema for isdlpenabled transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class DLPRule(BaseModel):
    """Single DLP rule from Zscaler ZIA."""

    state: Optional[str] = None
    status: Optional[str] = None
    enabled: Optional[bool] = None

    class Config:
        extra = "allow"


class IsdlpenabledInput(BaseModel):
    """
    Expected input schema for the isdlpenabled transformation.
    Criteria key: isDLPEnabled

    Checks for DLP rules, dictionaries, and engine configuration
    in Zscaler ZIA.
    """

    dlpRules: Optional[List[DLPRule]] = None
    responseData: Optional[List[Any]] = None
    dlpDictionaries: Optional[List[Dict[str, Any]]] = None
    dlpEnabled: Optional[bool] = None
    dlpEngineEnabled: Optional[bool] = None

    class Config:
        extra = "allow"
