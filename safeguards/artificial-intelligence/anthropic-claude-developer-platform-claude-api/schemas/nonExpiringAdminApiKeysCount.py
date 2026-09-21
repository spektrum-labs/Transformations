from pydantic import BaseModel


class NonExpiringAdminApiKeysCountInput(BaseModel):
    """Input schema for the nonExpiringAdminApiKeysCount transformation."""

    class Config:
        extra = "allow"
