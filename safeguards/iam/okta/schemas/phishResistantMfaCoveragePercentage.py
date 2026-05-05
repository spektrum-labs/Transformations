from pydantic import BaseModel
from typing import Any, Dict, List, Optional


class PhishResistantMfaCoveragePercentageInput(BaseModel):
    """
    Input schema for the phishResistantMfaCoveragePercentage transformation.

    Accepts a list of Okta Access Policy objects (type=ACCESS_POLICY) returned
    by GET /api/v1/policies?type=ACCESS_POLICY&expand=rules. Each object may
    contain _embedded.rules with verificationMethod.constraints.possession.phishingResistant.
    """

    class Config:
        extra = "allow"
