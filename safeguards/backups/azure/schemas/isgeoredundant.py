"""Schema for isgeoredundant transformation input."""
from typing import Optional
from pydantic import BaseModel, Field


class GeoRedundantProperties(BaseModel):
    """Properties containing storage type configuration."""
    storageType: Optional[str] = Field(
        default=None,
        description="Storage replication type (e.g., GeoRedundant, LocallyRedundant, ZoneRedundant)"
    )

    class Config:
        extra = "allow"


class IsgeoredundantInput(BaseModel):
    """Expected input schema for the isgeoredundant transformation. Criteria key: isGeoRedundant"""
    properties: Optional[GeoRedundantProperties] = Field(
        default=None,
        description="Properties containing storage type for geo-redundancy evaluation"
    )

    class Config:
        extra = "allow"
