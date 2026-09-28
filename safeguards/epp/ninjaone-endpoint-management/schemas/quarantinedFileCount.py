from pydantic import BaseModel


class QuarantinedFileCountInput(BaseModel):
    """Input schema for the quarantinedFileCount transformation."""

    class Config:
        extra = "allow"
