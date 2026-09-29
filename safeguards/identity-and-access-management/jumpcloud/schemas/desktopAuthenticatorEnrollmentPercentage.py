from pydantic import BaseModel


class DesktopAuthenticatorEnrollmentPercentageInput(BaseModel):
    """Input schema for the desktopAuthenticatorEnrollmentPercentage transformation."""

    class Config:
        extra = "allow"
