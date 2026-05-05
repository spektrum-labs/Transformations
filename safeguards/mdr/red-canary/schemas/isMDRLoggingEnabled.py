from pydantic import BaseModel
from typing import Any, Dict, List, Optional


class IsMDRLoggingEnabledInput(BaseModel):
    """Input schema for the isMDRLoggingEnabled transformation.

    Expects the Red Canary getEndpoints API response with a 'data' array of
    endpoint records and a 'meta' object containing total_items.
    """

    class Config:
        extra = "allow"
