from pydantic import BaseModel


class SuperAdminMfaEnrollmentPercentageInput(BaseModel):
    """Input schema for the superAdminMfaEnrollmentPercentage transformation."""

    class Config:
        extra = "allow"
