from pydantic import BaseModel


class IsAdminMFAPhishingResistantInput(BaseModel):
    """Input schema for the isAdminMFAPhishingResistant transformation."""

    class Config:
        extra = "allow"
