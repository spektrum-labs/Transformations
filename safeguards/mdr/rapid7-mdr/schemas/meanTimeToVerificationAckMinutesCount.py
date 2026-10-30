from pydantic import BaseModel


class MeanTimeToVerificationAckMinutesCountInput(BaseModel):
    """Input schema for the meanTimeToVerificationAckMinutesCount transformation."""

    class Config:
        extra = "allow"
