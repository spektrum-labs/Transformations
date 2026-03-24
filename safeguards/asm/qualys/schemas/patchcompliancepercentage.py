"""Schema for patchcompliancepercentage transformation input."""
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class PatchcompliancepercentageInput(BaseModel):
    """Expected input schema for the patchcompliancepercentage transformation. Criteria key: patchCompliancePercentage"""
    HOST_LIST_VM_DETECTION_OUTPUT: Optional[Dict] = Field(None, description="Qualys host list VM detection output")

    class Config:
        extra = "allow"
