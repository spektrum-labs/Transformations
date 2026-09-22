from pydantic import BaseModel


class IsAdvancedSecurityEnabledInput(BaseModel):
    """Input schema for the isAdvancedSecurityEnabled transformation."""

    class Config:
        extra = "allow"
