"""Schema for maliciousdomainblockrate transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class MaliciousdomainblockrateInput(BaseModel):
    """
    Expected input schema for the maliciousdomainblockrate transformation.
    Criteria key: maliciousDomainBlockRate

    summaries-by-category/dns returns {meta, data:[{category, summary}]}. Note that
    'data' is one of the keys the platform unwraps, so the transformation may receive
    the bare row list instead of the envelope.
    """

    meta: Optional[Dict[str, Any]] = None
    data: Optional[List[Dict[str, Any]]] = None
    category: Optional[Dict[str, Any]] = None
    summary: Optional[Dict[str, Any]] = None

    class Config:
        extra = "allow"
