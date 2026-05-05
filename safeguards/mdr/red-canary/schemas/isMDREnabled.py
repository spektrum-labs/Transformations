from pydantic import BaseModel
from typing import Any, Dict, List, Optional


class IsMDREnabledInput(BaseModel):
    """Input schema for the isMDREnabled transformation.

    Represents the response shape from Red Canary GET /openapi/v3/endpoints.
    The meta.total_items field is the primary signal used to determine whether
    the MDR service is active and connected to the customer environment.
    """

    class Config:
        extra = "allow"
