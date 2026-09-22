from pydantic import BaseModel


class IsAnalystVettedAlertPipelineEnabledInput(BaseModel):
    """Input schema for the isAnalystVettedAlertPipelineEnabled transformation."""

    class Config:
        extra = "allow"
