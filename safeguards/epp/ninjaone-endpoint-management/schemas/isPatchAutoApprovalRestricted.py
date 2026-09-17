from pydantic import BaseModel


class IsPatchAutoApprovalRestrictedInput(BaseModel):
    """Input schema for the isPatchAutoApprovalRestricted transformation.

    Expects the raw or enriched response from NinjaOne's GET /v2/policies
    endpoint: a list of policy objects, each optionally carrying a
    `conditions` array that may encode patch-approval mode settings.
    """

    class Config:
        extra = "allow"
