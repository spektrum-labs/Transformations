"""Schema for isbackupenabledforcriticalsystems transformation input."""

from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, Field


class Server(BaseModel):
    """Single server/client entry for backup coverage evaluation."""
    planId: Optional[Union[int, str]] = None
    backupPlanId: Optional[Union[int, str]] = None
    planName: Optional[str] = None
    assignedPlan: Optional[str] = None
    configured: Optional[Union[bool, str]] = None
    isConfigured: Optional[Union[bool, str]] = None
    lastBackupTime: Optional[Union[int, str]] = None
    lastBackupJobTime: Optional[Union[int, str]] = None

    class Config:
        extra = "allow"


class IsbackupenabledforcriticalsystemsInput(BaseModel):
    """
    Expected input schema for the isbackupenabledforcriticalsystems transformation.
    Criteria key: isBackupEnabledForCriticalSystems
    """
    fileServers: Optional[List[Server]] = None
    servers: Optional[List[Server]] = None
    clients: Optional[List[Server]] = None
    clientList: Optional[List[Server]] = None
    value: Optional[List[Server]] = None

    class Config:
        extra = "allow"
