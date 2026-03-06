"""Schema for istrainingcompletiontracked transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class IstrainingcompletiontrackedInput(BaseModel):
    """
    Expected input schema for the istrainingcompletiontracked transformation.
    Criteria key: isTrainingCompletionTracked

    Ensures training completion is tracked by checking the learners
    endpoint for enrolled users and their completion status.
    """

    learners: Optional[List[Dict[str, Any]]] = None
    data: Optional[List[Dict[str, Any]]] = None
    total: Optional[int] = None
    total_count: Optional[int] = None

    class Config:
        extra = "allow"
