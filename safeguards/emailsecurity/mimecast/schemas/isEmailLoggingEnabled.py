from pydantic import BaseModel
from typing import Any, Dict, List, Optional


class IsEmailLoggingEnabledInput(BaseModel):
    """Input schema for the isEmailLoggingEnabled transformation.

    Expects a Mimecast getAccount API response containing account-level
    metadata including the packages array which lists all licensed products.
    """

    fail: Optional[List[Any]] = None
    meta: Optional[Dict[str, Any]] = None
    data: Optional[List[Dict[str, Any]]] = None

    class Config:
        extra = "allow"
