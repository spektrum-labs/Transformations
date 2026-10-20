from pydantic import BaseModel


class StaleEvidenceArtifactsCountInput(BaseModel):
    """Input schema for the staleEvidenceArtifactsCount transformation."""

    class Config:
        extra = "allow"
