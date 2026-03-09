"""Schema for confirmedlicensepurchased transformation input."""

from typing import Optional

from pydantic import BaseModel, Field


class ConfirmedlicensepurchasedInput(BaseModel):
    """
    Expected input schema for the confirmedlicensepurchased transformation.

    Criteria key: confirmedLicensePurchased

    Evaluates whether the AppOmni subscription status is active or trial.
    """

    status: Optional[str] = Field(
        None,
        description="Subscription status, e.g. 'active' or 'trial'.",
    )
    plan: Optional[str] = Field(
        None,
        description="Subscription plan name.",
    )

    class Config:
        extra = "allow"
