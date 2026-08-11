from pydantic import BaseModel


class OpenQuarantinedMessagesCountInput(BaseModel):
    """Input schema for the openQuarantinedMessagesCount transformation."""

    class Config:
        extra = "allow"
