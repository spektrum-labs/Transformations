"""Schema for openhighriskappscount transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class OpenhighriskappscountInput(BaseModel):
    """
    Expected input schema for the openhighriskappscount transformation.
    Criteria key: openHighRiskAppsCount

    Same App Discovery envelope, filtered server-side to weightedRisk=high and
    weightedRisk=veryHigh via a repeated query parameter.
    """

    items: Optional[List[Dict[str, Any]]] = None
    itemsCount: Optional[int] = None
    currentPage: Optional[int] = None
    totalPages: Optional[int] = None

    class Config:
        extra = "allow"
