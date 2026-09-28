from pydantic import BaseModel


class SmsFactorEnabledUsersCountInput(BaseModel):
    """Input schema for the smsFactorEnabledUsersCount transformation."""

    class Config:
        extra = "allow"
