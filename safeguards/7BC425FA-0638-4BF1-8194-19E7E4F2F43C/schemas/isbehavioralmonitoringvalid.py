"""Schema for isbehavioralmonitoringvalid transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class IsbehavioralmonitoringvalidInput(BaseModel):
    """
    Expected input schema for the isbehavioralmonitoringvalid transformation.
    Criteria key: isbehavioralmonitoringvalid
    """

    odata_context: Optional[str] = Field(default=None, alias="@odata.context")
    value: Optional[List[Optional[Dict[str, Any]]]] = None

    class Config:
        extra = "allow"
