"""Schema for iscontinuousdiscoveryenabled transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class IscontinuousdiscoveryenabledInput(BaseModel):
    """
    Expected input schema for the iscontinuousdiscoveryenabled transformation.
    Criteria key: isContinuousDiscoveryEnabled

    App Discovery returns a paging envelope: items plus currentPage / totalPages /
    itemsCount. itemsCount is the authoritative fleet-wide total; items is one page.
    """

    items: Optional[List[Dict[str, Any]]] = None
    itemsCount: Optional[int] = None
    currentPage: Optional[int] = None
    totalPages: Optional[int] = None

    class Config:
        extra = "allow"
