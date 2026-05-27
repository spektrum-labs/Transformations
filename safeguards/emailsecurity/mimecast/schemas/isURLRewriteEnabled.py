from pydantic import BaseModel
from typing import Any, Dict, List, Optional


class IsURLRewriteEnabledInput(BaseModel):
    """Input schema for the isURLRewriteEnabled transformation.

    Accepts the response from getTTPUrlManagedUrls:
      - fail: list of API-level error objects
      - meta.pagination.totalCount: fleet-wide count of managed URL rules
      - data: sampled page of managed URL entries, each with disableRewrite field
    """

    fail: Optional[List[Any]] = None
    meta: Optional[Dict[str, Any]] = None
    data: Optional[List[Dict[str, Any]]] = None

    class Config:
        extra = "allow"
