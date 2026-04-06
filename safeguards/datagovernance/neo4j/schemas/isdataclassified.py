"""Schema for isdataclassified transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class IsdataclassifiedInput(BaseModel):
    """
    Expected input schema for the isdataclassified transformation.
    Vendor: Neo4J
    Category: datagovernance

    Note: No API response sample available. Schema structure should be
    updated based on actual API response format.
    """

    class Config:
        extra = "allow"
