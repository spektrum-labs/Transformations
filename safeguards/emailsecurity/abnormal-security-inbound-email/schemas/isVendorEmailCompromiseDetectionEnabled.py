from pydantic import BaseModel


class IsVendorEmailCompromiseDetectionEnabledInput(BaseModel):
    """Input schema for the isVendorEmailCompromiseDetectionEnabled transformation."""

    class Config:
        extra = "allow"
