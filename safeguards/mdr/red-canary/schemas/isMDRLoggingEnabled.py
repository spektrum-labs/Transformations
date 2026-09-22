
from pydantic import BaseModel
from typing import Any, Dict, List, Optional


class IsMDRLoggingEnabledInput(BaseModel):
    """Input schema for the isMDRLoggingEnabled transformation.

    Expects the Red Canary GET /openapi/v3/endpoints response with:
      - data: list of endpoint objects
      - meta.total_items: fleet-aggregate enrolled endpoint count
    """

    data: Optional[List[Dict[str, Any]]] = None
    meta: Optional[Dict[str, Any]] = None

    class Config:
        extra = "allow"
