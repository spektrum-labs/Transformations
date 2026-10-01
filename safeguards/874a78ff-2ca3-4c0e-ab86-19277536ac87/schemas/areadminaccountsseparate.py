"""Schema for areadminaccountsseparate transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class GraphListBody(BaseModel):
    """A Microsoft Graph list body: {"value": [...], "@odata.nextLink": ...}."""

    value: List[Dict[str, Any]] = Field(default_factory=list)

    class Config:
        extra = "allow"


class AreadminaccountsseparateInput(BaseModel):
    """
    Expected input schema for the areadminaccountsseparate transformation.

    A two-step workflow merges two Microsoft Graph reads:
      roleAssignments: GET /v1.0/roleManagement/directory/roleAssignments?$expand=principal($select=id)
                       rows carry roleDefinitionId, principalId and principal.@odata.type
      users:           GET /v1.0/users?$select=id,userPrincipalName,mail,accountEnabled,assignedLicenses
                       [,assignedPlans]&$top=999
    directoryRoles (GET /v1.0/directoryRoles?$expand=members) is accepted in place of
    roleAssignments. Microsoft Secure Score bodies are rejected as not evidence.
    """

    roleAssignments: Optional[GraphListBody] = None
    directoryRoles: Optional[GraphListBody] = None
    users: Optional[GraphListBody] = None

    class Config:
        extra = "allow"
