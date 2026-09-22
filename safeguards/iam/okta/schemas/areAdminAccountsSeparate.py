from pydantic import BaseModel
from typing import Any, Dict, List, Optional


class AreAdminAccountsSeparateInput(BaseModel):
    """Input schema for the areAdminAccountsSeparate transformation.

    Accepts the Okta listUsers API response. The response is an array of user
    objects returned under the 'apiResponse' envelope key. Each user object
    may contain an 'id', 'status', and 'profile' sub-object with 'login' and
    'email' fields used for admin-account heuristic detection.
    """

    apiResponse: Optional[List[Dict[str, Any]]] = None

    class Config:
        extra = "allow"
