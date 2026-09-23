from pydantic import BaseModel


class BypassStatusUsersCountInput(BaseModel):
    """Input schema for the bypassStatusUsersCount transformation."""

    class Config:
        extra = "allow"
