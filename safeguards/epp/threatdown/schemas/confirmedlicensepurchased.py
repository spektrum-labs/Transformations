"""Schema for confirmedlicensepurchased transformation input."""
from typing import Any, Dict, Optional, Union

from pydantic import BaseModel, Field


class SubscriptionInfo(BaseModel):
    """Subscription/license details from the ThreatDown account."""
    status: Optional[str] = Field(None, description="Subscription status (e.g. active, expired)")
    state: Optional[str] = Field(None, description="Alternate status field")
    plan: Optional[str] = Field(None, description="Subscription plan/tier name")
    tier: Optional[str] = Field(None, description="Alternate plan/tier field")
    type: Optional[str] = Field(None, description="Subscription type")

    class Config:
        extra = "allow"


class ConfirmedlicensepurchasedInput(BaseModel):
    """Expected input schema for the confirmedlicensepurchased transformation.
    Criteria key: confirmedLicensePurchased
    Source: ThreatDown Nebula /nebula/v1/account endpoint."""
    name: Optional[str] = Field(None, description="Account name")
    accountName: Optional[str] = Field(None, description="Alternate account name field")
    id: Optional[Union[str, int]] = Field(None, description="Account ID")
    accountId: Optional[str] = Field(None, description="Alternate account ID field")
    status: Optional[str] = Field(None, description="Account status (e.g. active, disabled)")
    state: Optional[str] = Field(None, description="Alternate status field")
    accountStatus: Optional[str] = Field(None, description="Alternate status field")
    subscription: Optional[SubscriptionInfo] = Field(None, description="Subscription/license details")
    license: Optional[SubscriptionInfo] = Field(None, description="Alternate subscription field")

    class Config:
        extra = "allow"
