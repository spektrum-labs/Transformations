from pydantic import BaseModel


class CustomDetectionRuleCountInput(BaseModel):
    """Input schema for the customDetectionRuleCount transformation."""

    class Config:
        extra = "allow"
