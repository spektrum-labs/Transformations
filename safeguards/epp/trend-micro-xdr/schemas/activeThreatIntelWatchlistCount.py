from pydantic import BaseModel


class ActiveThreatIntelWatchlistCountInput(BaseModel):
    """Input schema for the activeThreatIntelWatchlistCount transformation."""

    class Config:
        extra = "allow"
