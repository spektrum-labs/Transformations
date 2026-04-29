from pydantic import BaseModel
from typing import Any, Dict, List, Optional


class IsEmailLoggingEnabledInput(BaseModel):
    """Input schema for the isEmailLoggingEnabled transformation.

    Expects the Mimecast get-account API response with a data array containing
    the account record, including a packages list of provisioned product strings.
    """

    data: Optional[List[Any]] = None
    meta: Optional[Dict[str, Any]] = None
    fail: Optional[List[Any]] = None

    class Config:
        extra = "allow"
