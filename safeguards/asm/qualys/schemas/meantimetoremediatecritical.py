"""Schema for meantimetoremediatecritical transformation input."""
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class MeantimetoremediatecriticalInput(BaseModel):
    """Expected input schema for the meantimetoremediatecritical transformation. Criteria key: meanTimeToRemediateCritical"""
    HOST_LIST_VM_DETECTION_OUTPUT: Optional[Dict] = Field(None, description="Qualys host list VM detection output")

    class Config:
        extra = "allow"
