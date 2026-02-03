"""Schema for confirmedlicensepurchased transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ConfirmedlicensepurchasedInput(BaseModel):
    """
    Expected input schema for the confirmedlicensepurchased transformation.
    Criteria key: confirmedlicensepurchased
    """

    guid: Optional[str] = None
    custom_id: Optional[Any] = None
    name: Optional[str] = None
    description: Optional[str] = None
    ipv4_count: Optional[int] = None
    people_count: Optional[int] = None
    shortname: Optional[str] = None
    industry: Optional[str] = None
    industry_slug: Optional[str] = None
    sub_industry: Optional[str] = None
    sub_industry_slug: Optional[str] = None
    homepage: Optional[str] = None
    primary_domain: Optional[str] = None
    type: Optional[str] = None
    display_url: Optional[str] = None
    rating_details: Optional[Dict[str, Any]] = None
    ratings: Optional[List[Optional[Dict[str, Any]]]] = None
    search_count: Optional[int] = None
    subscription_type: Optional[str] = None
    sparkline: Optional[str] = None
    subscription_type_key: Optional[str] = None
    subscription_end_date: Optional[Any] = None
    bulk_email_sender_status: Optional[str] = None
    service_provider: Optional[bool] = None
    customer_monitoring_count: Optional[int] = None
    available_upgrade_types: Optional[List[Any]] = None
    has_company_tree: Optional[bool] = None
    has_preferred_contact: Optional[bool] = None
    is_bundle: Optional[bool] = None
    rating_industry_median: Optional[str] = None
    primary_company: Optional[Any] = None
    permissions: Optional[Dict[str, Any]] = None
    is_primary: Optional[bool] = None
    security_grade: Optional[Any] = None
    in_spm_portfolio: Optional[bool] = None
    is_mycomp_mysubs_bundle: Optional[bool] = None
    company_features: Optional[List[Any]] = None
    compliance_claim: Optional[Any] = None
    is_csp: Optional[bool] = None
    related_companies: Optional[List[Any]] = None
    has_delegated_security_controls: Optional[bool] = None
    current_rating: Optional[int] = None

    class Config:
        extra = "allow"
