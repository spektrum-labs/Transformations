"""Schema for isphishingsimulationenabled transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class IsphishingsimulationenabledInput(BaseModel):
    """
    Expected input schema for the isphishingsimulationenabled transformation.
    Criteria key: isPhishingSimulationEnabled

    Consumes /api/v1/accounts/{accountId}/phishing-campaigns from Huntress SAT
    (Curricula), a JSON:API list:
      {"data": [{"type": "phishing-campaigns", "id": "...", "attributes": {title, status, campaignLaunchedAt, ...}}, ...],
       "meta": {"page": {"total": N, ...}}}
    Token-Service preprocessing reduces this to the bare list of items.
    """

    data: Optional[List[Dict[str, Any]]] = None
    meta: Optional[Dict[str, Any]] = None

    class Config:
        extra = "allow"
