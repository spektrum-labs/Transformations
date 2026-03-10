"""Schema for isairgapprotectenabled transformation input."""

from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, Field


class StoragePool(BaseModel):
    """Single storage pool entry for air gap evaluation."""
    storageType: Optional[str] = None
    type: Optional[str] = None
    name: Optional[str] = None
    storagePoolName: Optional[str] = None
    isAirGapProtect: Optional[Union[bool, str]] = None
    airGapProtectEnabled: Optional[Union[bool, str]] = None
    metallic: Optional[Union[bool, str]] = None

    class Config:
        extra = "allow"


class IsairgapprotectenabledInput(BaseModel):
    """
    Expected input schema for the isairgapprotectenabled transformation.
    Criteria key: isAirGapProtectEnabled
    """
    storagePoolList: Optional[List[StoragePool]] = None
    storagePool: Optional[List[StoragePool]] = None
    storagePolicies: Optional[List[StoragePool]] = None

    class Config:
        extra = "allow"
