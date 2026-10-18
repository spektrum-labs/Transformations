from pydantic import BaseModel


class SuspendedUsersCountInput(BaseModel):
    """Input schema for the suspendedUsersCount transformation."""

    class Config:
        extra = "allow"
