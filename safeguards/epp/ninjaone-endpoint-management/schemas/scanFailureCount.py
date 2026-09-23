from pydantic import BaseModel


class ScanFailureCountInput(BaseModel):
    """Input schema for the scanFailureCount transformation."""

    class Config:
        extra = "allow"
