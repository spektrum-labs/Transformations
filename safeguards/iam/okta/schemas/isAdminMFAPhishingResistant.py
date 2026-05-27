
from pydantic import BaseModel
from typing import List, Optional


class IsAdminMFAPhishingResistantInput(BaseModel):
    """
    Input schema for the isAdminMFAPhishingResistant transformation.
    Represents the Okta listOrgFactors API response, which returns an array
    of org-level factor objects each with factorType, provider, and status.
    The raw API returns a top-level array; it may also arrive wrapped in
    an apiResponse or factors key depending on the runtime envelope.
    """

    class Config:
        extra = "allow"
