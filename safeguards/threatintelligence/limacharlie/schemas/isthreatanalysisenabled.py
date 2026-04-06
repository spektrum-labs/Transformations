"""Schema for isthreatanalysisenabled transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class IsthreatanalysisenabledInput(BaseModel):
    """
    Expected input schema for the isthreatanalysisenabled transformation.
    Vendor: Limacharlie
    Category: threatintelligence

    Note: No API response sample available. Schema structure should be
    updated based on actual API response format.
    """

    class Config:
        extra = "allow"
