from pydantic import BaseModel
from typing import Any, Dict, List, Optional


class IsAdminMFAPhishingResistantInput(BaseModel):
    """
    Input schema for the isAdminMFAPhishingResistant transformation.

    Represents the Okta ACCESS_POLICY API response (type=ACCESS_POLICY&expand=rules).
    Each element in the list is a policy object with optional _embedded.rules containing
    verificationMethod.constraints[].possession.phishingResistant fields.
    """

    class Config:
        extra = "allow"
