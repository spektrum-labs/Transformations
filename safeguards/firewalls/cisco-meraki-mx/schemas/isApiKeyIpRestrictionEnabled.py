from pydantic import BaseModel


class IsApiKeyIpRestrictionEnabledInput(BaseModel):
    """Input schema for the isApiKeyIpRestrictionEnabled transformation."""

    class Config:
        extra = "allow"
