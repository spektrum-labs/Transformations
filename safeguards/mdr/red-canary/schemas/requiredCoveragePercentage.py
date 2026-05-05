from pydantic import BaseModel
from typing import Any, Dict, List, Optional


class RequiredCoveragePercentageInput(BaseModel):
    """Input schema for the requiredCoveragePercentage transformation.

    Accepts the getEndpoints API response envelope from Red Canary.
    meta.total_items provides the fleet-wide enrolled endpoint count.
    An optional config/settings block provides the expectedDeviceCount
    denominator from the per-tenant safeguard configuration.
    """

    class Config:
        extra = "allow"
