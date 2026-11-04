from pydantic import BaseModel
from typing import Optional, List, Any


class NumActiveDataConnectorsInput(BaseModel):
    """Input schema for the numActiveDataConnectors transformation (Sumo Logic getCollectors response)."""

    collectors: Optional[List[Any]] = None

    class Config:
        extra = "allow"
