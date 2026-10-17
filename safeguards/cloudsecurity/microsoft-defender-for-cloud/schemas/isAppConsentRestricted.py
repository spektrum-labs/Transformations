from pydantic import BaseModel


class IsAppConsentRestrictedInput(BaseModel):
    """Input schema for the isAppConsentRestricted transformation."""

    class Config:
        extra = "allow"
