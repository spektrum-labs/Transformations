"""Schema for istrainingenabled transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class IstrainingenabledInput(BaseModel):
    """
    Expected input schema for the istrainingenabled transformation.
    Criteria key: isTrainingEnabled

    Consumes /api/v1/accounts/{accountId}/assignments from Huntress SAT (Curricula),
    a JSON:API list:
      {"data": [{"type": "assignments", "id": "...", "attributes": {name, status, startsAt, endsAt, ...}}, ...],
       "meta": {"page": {"total": N, ...}}}
    Token-Service preprocessing reduces this to the bare list of items.
    """

    data: Optional[List[Dict[str, Any]]] = None
    meta: Optional[Dict[str, Any]] = None

    class Config:
        extra = "allow"
