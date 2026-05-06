from pydantic import BaseModel
from typing import Any, Dict, List, Optional


class IsDNSLoggingEnabledInput(BaseModel):
    """Input schema for the isDNSLoggingEnabled transformation.

    Accepts the DNSFilter getQueryLogs response envelope. The key fields are:
    - data.values: list of DNS query log entries for the current page
    - data.page.total: aggregate count of all log entries across all pages
    - data.organization_name: name of the organization being evaluated
    """

    class Config:
        extra = "allow"
