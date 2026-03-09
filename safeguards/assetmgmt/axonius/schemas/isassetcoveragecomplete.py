"""Schema for isassetcoveragecomplete transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class IsassetcoveragecompleteInput(BaseModel):
    """
    Expected input schema for the isassetcoveragecomplete transformation.

    Axonius devices API response containing asset coverage data.
    """

    assets: Optional[List[Dict[str, Any]]] = Field(None, description="List of discovered assets")
    data: Optional[List[Dict[str, Any]]] = Field(None, description="Alternative data array of assets")
    devices: Optional[List[Dict[str, Any]]] = Field(None, description="Alternative devices array")
    page: Optional[Dict[str, Any]] = Field(None, description="Pagination info with totalResources")

    class Config:
        extra = "allow"
