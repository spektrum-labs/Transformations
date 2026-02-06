"""Schema for confirmedlicensepurchased transformation input."""

from typing import Any, Optional
from pydantic import BaseModel, Field


class ConfirmedLicensePurchasedInput(BaseModel):
    """
    Expected input schema for the confirmedlicensepurchased transformation.

    This schema validates the API response structure before transformation.
    The transformation checks if a license has been purchased for the backup provider.
    """

    licensePurchased: Optional[bool] = Field(
        default=None,
        description="Whether the license has been purchased for the backup provider"
    )
    rawResponse: Optional[Any] = Field(
        default=None,
        description="Raw AWS API response (DescribeDBInstancesResponse)"
    )

    class Config:
        extra = "allow"  # Allow additional fields for forward compatibility
