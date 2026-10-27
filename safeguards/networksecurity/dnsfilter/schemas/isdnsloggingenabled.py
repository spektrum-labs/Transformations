"""Schema for isdnsloggingenabled transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel


class TrafficReportsTotalRequests(BaseModel):
    """GET /v1/traffic_reports/total_requests (DNSFilter OpenAPI TrafficReportsTotalRequests):
    one bucket per period in `values`, each with `total`."""

    organization_ids: Optional[List[int]] = None
    organization_names: Optional[List[str]] = None
    network_ids: Optional[List[Any]] = None
    network_names: Optional[List[Any]] = None
    values: Optional[List[Dict[str, Any]]] = None

    class Config:
        extra = "allow"


class IsdnsloggingenabledInput(TrafficReportsTotalRequests):
    """
    Expected input schema for the isdnsloggingenabled transformation.
    Criteria key: isDNSLoggingEnabled

    The report fields sit at the top level (Token-Service strips the vendor's `data`
    wrapper before validating); a raw body keeps them under `data`. A vendor error
    envelope (neither) still validates; the transform reports it as not measured.
    """

    data: Optional[TrafficReportsTotalRequests] = None
