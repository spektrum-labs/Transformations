from pydantic import BaseModel


class LockedOutUsersCountInput(BaseModel):
    """Input schema for the lockedOutUsersCount transformation."""

    class Config:
        extra = "allow"
