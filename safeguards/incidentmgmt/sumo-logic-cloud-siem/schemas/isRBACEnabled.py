from pydantic import BaseModel
from typing import Optional, List, Any


class IsRBACEnabledInput(BaseModel):
    """Input schema for the isRBACEnabled transformation (getRoles response)."""

    data: Optional[List[Any]] = None

    class Config:
        extra = "allow"
