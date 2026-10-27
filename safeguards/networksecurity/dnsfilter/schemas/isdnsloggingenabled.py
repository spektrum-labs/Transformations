"""Schema for isdnsloggingenabled transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel


class TrafficReportsTotalRequests(BaseModel):
    """The `data` object of GET /v1/traffic_reports/total_requests (DNSFilter OpenAPI
    TrafficReportsTotalRequests). `values` holds one bucket per period with `total`."""

    organization_ids: Optional[List[int]] = None
    organization_names: Optional[List[str]] = None
    network_ids: Optional[List[Any]] = None
    network_names: Optional[List[Any]] = None
    values: Optional[List[Dict[str, Any]]] = None

    class Config:
        extra = "allow"


class IsdnsloggingenabledInput(BaseModel):
    """
    Expected input schema for the isdnsloggingenabled transformation.
    Criteria key: isDNSLoggingEnabled

    Validates that DNS query logging is enabled by summing the query totals of
    the total_requests traffic report over the Integration-Service window.
    Token-Service strips the vendor's `data` wrapper before validating, so the
    report fields sit at the top level; a raw body keeps them under `data`.
    A vendor error envelope (neither) still validates; the transform reports it
    as not measured.
    """

    organization_ids: Optional[List[int]] = None
    organization_names: Optional[List[str]] = None
    network_ids: Optional[List[Any]] = None
    network_names: Optional[List[Any]] = None
    values: Optional[List[Dict[str, Any]]] = None
    data: Optional[TrafficReportsTotalRequests] = None

    class Config:
        extra = "allow"
