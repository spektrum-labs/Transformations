"""Schema for confirmedlicensepurchased transformation input."""
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class PersonItem(BaseModel):
    """A person entry from the ZenGRC people API."""
    name: Optional[str] = Field(None, description="Person's full name")
    email: Optional[str] = Field(None, description="Person's email address")
    role: Optional[str] = Field(None, description="Person's role in ZenGRC")
    status: Optional[str] = Field(None, description="Person's status (active, inactive)")

    class Config:
        extra = "allow"


class ConfirmedlicensepurchasedInput(BaseModel):
    """Expected input schema for the confirmedlicensepurchased transformation.
    Criteria key: confirmedLicensePurchased
    Source: ZenGRC GET /api/v2/people"""
    data: Optional[List[PersonItem]] = Field(None, description="JSON:API data array of people")
    people: Optional[List[PersonItem]] = Field(None, description="Alternate people list field")
    results: Optional[List[PersonItem]] = Field(None, description="Alternate results field")
    meta: Optional[Dict[str, Any]] = Field(None, description="Pagination metadata with total count")

    class Config:
        extra = "allow"
