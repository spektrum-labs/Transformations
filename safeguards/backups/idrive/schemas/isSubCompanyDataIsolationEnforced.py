from pydantic import BaseModel


class IsSubCompanyDataIsolationEnforcedInput(BaseModel):
    """Input schema for the isSubCompanyDataIsolationEnforced transformation."""

    class Config:
        extra = "allow"
