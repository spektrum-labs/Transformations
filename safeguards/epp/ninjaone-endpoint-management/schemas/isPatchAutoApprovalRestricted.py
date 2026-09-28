from pydantic import BaseModel


class IsPatchAutoApprovalRestrictedInput(BaseModel):
    """Input schema for the isPatchAutoApprovalRestricted transformation."""

    class Config:
        extra = "allow"
