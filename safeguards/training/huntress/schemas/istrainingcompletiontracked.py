"""Schema for istrainingcompletiontracked transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class IstrainingcompletiontrackedInput(BaseModel):
    """
    Expected input schema for the istrainingcompletiontracked transformation.
    Criteria key: isTrainingCompletionTracked

    Consumes /api/v1/accounts/{accountId}/learners from Huntress SAT (Curricula),
    a JSON:API list:
      {"data": [{"type": "learners", "id": "...", "attributes": {firstName, lastName, email, status, doNotPhish, ...}}, ...],
       "meta": {"page": {"total": N, ...}}}
    Token-Service preprocessing reduces this to the bare list of items.
    """

    data: Optional[List[Dict[str, Any]]] = None
    meta: Optional[Dict[str, Any]] = None

    class Config:
        extra = "allow"
