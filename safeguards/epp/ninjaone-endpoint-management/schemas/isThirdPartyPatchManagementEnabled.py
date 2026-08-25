from pydantic import BaseModel
from typing import Optional, List, Any


class IsThirdPartyPatchManagementEnabledInput(BaseModel):
    """Input schema for the isThirdPartyPatchManagementEnabled transformation.

    Expects the getSoftwarePatchInstalls response shape:
    {"cursor": {...}, "results": [{"deviceId": int, "status": str, "timestamp": float, "patchName": str}, ...]}
    """

    cursor: Optional[Any] = None
    results: Optional[List[Any]] = None

    class Config:
        extra = "allow"
