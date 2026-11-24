from pydantic import BaseModel


class IsAuthEventCollectionEnabledInput(BaseModel):
    """Input schema for the isAuthEventCollectionEnabled transformation."""

    class Config:
        extra = "allow"
