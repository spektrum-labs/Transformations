from pydantic import BaseModel
from typing import Any, Dict, List, Optional


class RequiredCoveragePercentageInput(BaseModel):
    """Input schema for the requiredCoveragePercentage transformation.

    Expects the Red Canary getEndpoints response envelope.
    The `meta.total_items` field is the authoritative enrolled endpoint count.
    An optional `config` / `context` / `safeguard_config` dict may carry
    `expectedEndpoints` (the per-tenant fleet size denominator).
    """

    data: Optional[List[Any]] = None
    meta: Optional[Dict[str, Any]] = None
    config: Optional[Dict[str, Any]] = None
    context: Optional[Dict[str, Any]] = None
    safeguard_config: Optional[Dict[str, Any]] = None

    class Config:
        extra = "allow"
