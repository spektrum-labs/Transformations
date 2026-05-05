from pydantic import BaseModel
from typing import Any, Dict, List, Optional


class IsMDRLoggingEnabledInput(BaseModel):
    """Input schema for the isMDRLoggingEnabled transformation.

    Accepts the Red Canary getEndpoints API response envelope.
    data: list of endpoint objects, each optionally containing an attributes block
          with last_activity_at indicating the last telemetry received from that endpoint.
    meta: envelope metadata including total_items (total enrolled endpoints).
    """

    data: Optional[List[Dict[str, Any]]] = None
    meta: Optional[Dict[str, Any]] = None

    class Config:
        extra = "allow"
