from pydantic import BaseModel
from typing import Optional, List, Any


class RequiredCoveragePercentageInput(BaseModel):
    """Input schema for the requiredCoveragePercentage transformation.

    Expects the response shape from SentinelOne GET /web/api/v2.1/accounts.
    Key fields used: data[*].activeAgents, data[*].unlimitedComplete,
    data[*].unlimitedControl, data[*].unlimitedCore, data[*].name,
    data[*].accountType.
    """

    class Config:
        extra = "allow"
