"""Input schema for SonicWall built-in administrator TOTP configuration."""

from typing import Any, Dict, List, Optional

from pydantic import BaseModel


class Source(BaseModel):
    vendor: str
    product: str
    firmwareVersion: str
    apiContract: str
    authenticationMode: str

    class Config:
        extra = "allow"


class Collection(BaseModel):
    requiredEndpointsSucceeded: bool
    capabilityProfileRecognized: bool
    allExpectedResponseSectionsPresent: bool
    errors: List[str]

    class Config:
        extra = "allow"


class Counts(BaseModel):
    rawUserEntries: int
    rawGroupEntries: int

    class Config:
        extra = "allow"


class Evidence(BaseModel):
    localUsers: Dict[str, Any]
    localGroups: Optional[Dict[str, Any]] = None
    administrationGlobal: Dict[str, Any]

    class Config:
        extra = "allow"


class IsbuiltinadministratormfaboundInput(BaseModel):
    source: Source
    collection: Collection
    counts: Counts
    evidence: Evidence

    class Config:
        extra = "allow"
