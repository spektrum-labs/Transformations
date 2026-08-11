from pydantic import BaseModel


class IsScopedAPIAuthTokenManagedInput(BaseModel):
    """Input schema for the isScopedAPIAuthTokenManaged transformation."""

    class Config:
        extra = "allow"
