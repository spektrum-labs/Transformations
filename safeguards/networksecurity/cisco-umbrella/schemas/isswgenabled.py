"""Schema for isswgenabled transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class IsswgenabledInput(BaseModel):
    """
    Expected input schema for the isswgenabled transformation.
    Criteria key: isSWGEnabled

    Cisco Umbrella returns the roaming-computer fleet as a bare JSON array, so the
    platform hands the transformation a list rather than an envelope. The optional
    fields below cover the wrapped shapes the pipeline can also produce.
    """

    swgStatus: Optional[str] = None
    lastSyncSwgStatus: Optional[str] = None
    originId: Optional[int] = None
    name: Optional[str] = None
    data: Optional[List[Dict[str, Any]]] = None

    class Config:
        extra = "allow"
