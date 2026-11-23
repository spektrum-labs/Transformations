from pydantic import BaseModel


class IsJobExecutionLogAccessibleInput(BaseModel):
    """Input schema for the isJobExecutionLogAccessible transformation."""

    class Config:
        extra = "allow"
