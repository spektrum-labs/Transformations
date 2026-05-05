from pydantic import BaseModel
from typing import Any, Dict, List, Optional


class IsLegacyAuthBlockedInput(BaseModel):
    """
    Input schema for the isLegacyAuthBlocked transformation.

    Represents the response from the Okta listGlobalSessionPolicies API
    (GET /api/v1/policies?type=OKTA_SIGN_ON&expand=rules).

    The API returns a list of policy objects, each containing embedded rules
    with conditions (authContext.authType, clients) and actions (signon.access,
    signon.requireFactor) that determine legacy auth blocking posture.
    """

    class Config:
        extra = "allow"
