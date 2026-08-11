from pydantic import BaseModel


class IsSafeAttachmentsEnabledInput(BaseModel):
    """Input schema for the isSafeAttachmentsEnabled transformation."""

    class Config:
        extra = "allow"
