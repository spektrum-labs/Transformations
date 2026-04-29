from pydantic import BaseModel
from typing import Any, Dict, List, Optional


class IsDNSConfiguredInput(BaseModel):
    """Input schema for the isDNSConfigured transformation.

    Expects the raw response from the Mimecast getInternalDomain endpoint
    (POST /api/domain/get-internal-domain). Each item in data[] carries
    domain, sendOnly, local, and inboundType fields.
    """

    data: Optional[List[Dict[str, Any]]] = None
    meta: Optional[Dict[str, Any]] = None
    fail: Optional[List[Any]] = None

    class Config:
        extra = "allow"
