"""Schema for networksegmentationactive transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class NetworksegmentationactiveInput(BaseModel):
    """
    Expected input schema for the networksegmentationactive transformation.
    Criteria key: networkSegmentationActive
    """

    vlans: Optional[List[Dict]] = None

    class Config:
        extra = "allow"
