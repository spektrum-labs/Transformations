from pydantic import BaseModel


class HaModeEnabledInput(BaseModel):
    """Input schema for the haModeEnabled transformation."""

    class Config:
        extra = "allow"
