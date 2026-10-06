from pydantic import BaseModel
from typing import Any, Dict, List, Optional


class AreAdminAccountsSeparateInput(BaseModel):
    """Input schema for the areAdminAccountsSeparate transformation.

    Accepts the body of the Integration-Service workflow getAdminAppAssignments:
      adminAssignees  GET /api/v1/iam/assignees/users -> {"value": [{"id": ...}], "_links": {...}}
      adminAppLinks   GET /api/v1/users/{id}/appLinks per admin, index-aligned with
                      adminAssignees.value; a failed read is {"error": true, "statusCode", "item"}
      paginationStats / iterateStats  completeness markers reported by the workflow
    """

    adminAssignees: Optional[Dict[str, Any]] = None
    adminAppLinks: Optional[List[Any]] = None
    paginationStats: Optional[Dict[str, Any]] = None
    iterateStats: Optional[Dict[str, Any]] = None

    class Config:
        extra = "allow"
