"""Schema for ismfarequiredforcloudapps transformation input."""
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class IsmfarequiredforcloudappsInput(BaseModel):
    """
    Expected input schema for the ismfarequiredforcloudapps transformation.
    Criteria key: isMFARequiredForCloudApps
    """
    value: Optional[List[Dict[str, Any]]] = Field(None, description="List of Conditional Access policies")

    class Config:
        extra = "allow"
