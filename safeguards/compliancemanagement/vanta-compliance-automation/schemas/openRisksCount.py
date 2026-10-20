from pydantic import BaseModel


class OpenRisksCountInput(BaseModel):
    """Input schema for the openRisksCount transformation."""

    class Config:
        extra = "allow"
