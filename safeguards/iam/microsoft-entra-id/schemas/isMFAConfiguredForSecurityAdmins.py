from pydantic import BaseModel


class IsMFAConfiguredForSecurityAdminsInput(BaseModel):
    """Input schema for the isMFAConfiguredForSecurityAdmins transformation."""

    class Config:
        extra = "allow"
