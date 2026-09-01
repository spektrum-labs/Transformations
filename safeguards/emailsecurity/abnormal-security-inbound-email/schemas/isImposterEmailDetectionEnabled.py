from pydantic import BaseModel


class IsImposterEmailDetectionEnabledInput(BaseModel):
    """Input schema for the isImposterEmailDetectionEnabled transformation."""

    class Config:
        extra = "allow"
