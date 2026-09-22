"""Schema for confirmedlicensepurchased transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ConfirmedlicensepurchasedInput(BaseModel):
    """
    Expected input schema for the confirmedlicensepurchased transformation.
    Criteria key: confirmedLicensePurchased

    Consumes /api/v1/accounts/{accountId} from the Huntress SAT (Curricula)
    API, a single JSON:API record:
      {"data": {"type": "accounts", "id": "...", "attributes": {name, status, type, plan, ...}}}
    Token-Service preprocessing may pass the inner record directly.
    """

    type: Optional[str] = None
    id: Optional[str] = None
    attributes: Optional[Dict[str, Any]] = None
    data: Optional[Dict[str, Any]] = None

    class Config:
        extra = "allow"
