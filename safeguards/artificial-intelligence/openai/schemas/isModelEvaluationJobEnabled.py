from pydantic import BaseModel


class IsModelEvaluationJobEnabledInput(BaseModel):
    """Input schema for the isModelEvaluationJobEnabled transformation."""

    class Config:
        extra = "allow"
