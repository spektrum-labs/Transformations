from pydantic import BaseModel
from typing import Any, Dict, List, Optional


class AreAdminAccountsSeparateInput(BaseModel):
    """Input schema for the areAdminAccountsSeparate transformation.

    Accepts the body of the Integration-Service workflow getAdminAppAssignments:
      adminAssignees  GET /api/v1/iam/assignees/users -> {"value": [{"id": ...}], "_links": {...}}
      adminAppLinks   GET /api/v1/users/{id}/appLinks per admin, index-aligned with
                      adminAssignees.value; a failed read is {"error": true, "statusCode", "item"}
      paginationStats / iterateStats  completeness markers reported by the workflow
      orgApps             OPTIONAL GET /api/v1/apps?filter=status eq "ACTIVE" (list or {"value": [...]})
      sampleUserAppLinks  OPTIONAL appLinks for a page of active users (same shape as adminAppLinks)
    Without either optional field a run that finds no admin holding a productivity app is not evaluated.
    """

    adminAssignees: Optional[Dict[str, Any]] = None
    adminAppLinks: Optional[List[Any]] = None
    orgApps: Optional[Any] = None
    sampleUserAppLinks: Optional[List[Any]] = None
    paginationStats: Optional[Dict[str, Any]] = None
    iterateStats: Optional[Dict[str, Any]] = None

    class Config:
        extra = "allow"
