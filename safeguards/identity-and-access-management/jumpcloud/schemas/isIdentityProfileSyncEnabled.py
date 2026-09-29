from pydantic import BaseModel

class IsIdentityProfileSyncEnabledInput(BaseModel):
    """Input schema for the isIdentityProfileSyncEnabled transformation."""
    class Config:
        extra = "allow"
