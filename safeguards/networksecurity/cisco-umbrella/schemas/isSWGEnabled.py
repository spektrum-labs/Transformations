from pydantic import BaseModel


class IsSWGEnabledInput(BaseModel):
    """Input schema for the isSWGEnabled transformation."""

    class Config:
        extra = "allow"
