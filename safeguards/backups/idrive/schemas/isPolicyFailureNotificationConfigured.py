from pydantic import BaseModel


class IsPolicyFailureNotificationConfiguredInput(BaseModel):
    """Input schema for the isPolicyFailureNotificationConfigured transformation."""

    class Config:
        extra = "allow"
