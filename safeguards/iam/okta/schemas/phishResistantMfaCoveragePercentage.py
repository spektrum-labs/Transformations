from pydantic import BaseModel
from typing import Any, Dict, List, Optional


class PhishResistantMfaCoveragePercentageInput(BaseModel):
    """
    Input schema for the phishResistantMfaCoveragePercentage transformation.

    Accepts the listUsers response from Okta's /api/v1/users endpoint.
    The top-level response is wrapped in an 'apiResponse' list containing
    user objects with id, status, credentials, and profile fields.
    """
    apiResponse: Optional[List[Dict[str, Any]]] = None
    data: Optional[List[Dict[str, Any]]] = None

    class Config:
        extra = "allow"
