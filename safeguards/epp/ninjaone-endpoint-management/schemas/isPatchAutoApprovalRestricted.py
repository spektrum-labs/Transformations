from pydantic import BaseModel


class IsPatchAutoApprovalRestrictedInput(BaseModel):
    """Input schema for the isPatchAutoApprovalRestricted transformation.

    Accepts the getPolicies response shape (a list of policy objects, each
    potentially carrying nested approval/auto-approve settings), including
    the columnar-empty shape observed in this tenant's captured response.
    """

    class Config:
        extra = "allow"
