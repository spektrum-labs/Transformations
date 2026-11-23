from pydantic import BaseModel


class AdminMfaEnrollmentPercentageInput(BaseModel):
    """Input schema for the adminMfaEnrollmentPercentage transformation."""

    class Config:
        extra = "allow"
