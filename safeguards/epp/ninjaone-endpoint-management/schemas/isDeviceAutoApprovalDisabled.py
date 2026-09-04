from pydantic import BaseModel
from typing import Optional, List, Any


class IsDeviceAutoApprovalDisabledInput(BaseModel):
    """Input schema for the isDeviceAutoApprovalDisabled transformation.

    Expects the getOrganizations response: a list of organization objects,
    each carrying an id, name, and nodeApprovalMode (AUTOMATIC|MANUAL|REJECT).
    """

    class Config:
        extra = "allow"
