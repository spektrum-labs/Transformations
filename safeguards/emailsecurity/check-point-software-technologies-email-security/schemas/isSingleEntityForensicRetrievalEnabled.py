from pydantic import BaseModel


class IsSingleEntityForensicRetrievalEnabledInput(BaseModel):
    """Input schema for the isSingleEntityForensicRetrievalEnabled transformation."""

    class Config:
        extra = "allow"
