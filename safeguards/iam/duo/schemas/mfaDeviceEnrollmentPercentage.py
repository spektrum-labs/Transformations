from pydantic import BaseModel


class MfaDeviceEnrollmentPercentageInput(BaseModel):
    """Input schema for the mfaDeviceEnrollmentPercentage transformation."""

    class Config:
        extra = "allow"
