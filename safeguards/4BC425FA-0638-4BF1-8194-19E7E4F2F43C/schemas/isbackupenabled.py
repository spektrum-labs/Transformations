"""Schema for isbackupenabled transformation input."""

from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, Field


# --- DB Automated Backups ---

class DBInstanceAutomatedBackup(BaseModel):
    """Single automated backup record."""
    DBInstanceIdentifier: Optional[str] = None
    DBInstanceArn: Optional[str] = None
    Status: Optional[str] = None
    BackupRetentionPeriod: Optional[str] = None
    Encrypted: Optional[str] = None

    class Config:
        extra = "allow"


class DBInstanceAutomatedBackups(BaseModel):
    """Container for automated backup records."""
    DBInstanceAutomatedBackup: Optional[Union[DBInstanceAutomatedBackup, List[DBInstanceAutomatedBackup]]] = None

    class Config:
        extra = "allow"


class DescribeDBInstanceAutomatedBackupsResult(BaseModel):
    """Result from DescribeDBInstanceAutomatedBackups API."""
    DBInstanceAutomatedBackups: Optional[Union[DBInstanceAutomatedBackups, Dict[str, Any]]] = None

    class Config:
        extra = "allow"


class DescribeDBInstanceAutomatedBackupsResponse(BaseModel):
    """AWS RDS DescribeDBInstanceAutomatedBackups response."""
    DescribeDBInstanceAutomatedBackupsResult: Optional[DescribeDBInstanceAutomatedBackupsResult] = None
    ResponseMetadata: Optional[Dict[str, Any]] = None

    class Config:
        extra = "allow"


class DBBackups(BaseModel):
    """Container for DB automated backups response."""
    DescribeDBInstanceAutomatedBackupsResponse: Optional[DescribeDBInstanceAutomatedBackupsResponse] = None

    class Config:
        extra = "allow"


# --- DB Manual Snapshots ---

class DBSnapshot(BaseModel):
    """Single manual DB snapshot record."""
    DBSnapshotIdentifier: Optional[str] = None
    DBInstanceIdentifier: Optional[str] = None
    DBSnapshotArn: Optional[str] = None
    Status: Optional[str] = None
    SnapshotType: Optional[str] = None
    Encrypted: Optional[str] = None

    class Config:
        extra = "allow"


class DBSnapshots(BaseModel):
    """Container for DB snapshot records."""
    DBSnapshot: Optional[Union[DBSnapshot, List[DBSnapshot]]] = None

    class Config:
        extra = "allow"


class DescribeDBSnapshotsResult(BaseModel):
    """Result from DescribeDBSnapshots API."""
    DBSnapshots: Optional[Union[DBSnapshots, Dict[str, Any]]] = None

    class Config:
        extra = "allow"


class DescribeDBSnapshotsResponse(BaseModel):
    """AWS RDS DescribeDBSnapshots response."""
    DescribeDBSnapshotsResult: Optional[DescribeDBSnapshotsResult] = None
    ResponseMetadata: Optional[Dict[str, Any]] = None

    class Config:
        extra = "allow"


class DBManualSnapshots(BaseModel):
    """Container for DB manual snapshots response."""
    DescribeDBSnapshotsResponse: Optional[DescribeDBSnapshotsResponse] = None

    class Config:
        extra = "allow"


# --- EBS Volume Snapshots ---

class EBSSnapshot(BaseModel):
    """Single EBS volume snapshot record."""
    snapshotId: Optional[str] = None
    volumeId: Optional[str] = None
    status: Optional[str] = None
    encrypted: Optional[str] = None

    class Config:
        extra = "allow"


class SnapshotSet(BaseModel):
    """Container for EBS snapshot records."""
    item: Optional[Union[EBSSnapshot, List[EBSSnapshot]]] = None

    class Config:
        extra = "allow"


class DescribeSnapshotsResponse(BaseModel):
    """AWS EC2 DescribeSnapshots response."""
    requestId: Optional[str] = None
    snapshotSet: Optional[Union[SnapshotSet, None]] = None

    class Config:
        extra = "allow"


class VolumeSnapshots(BaseModel):
    """Container for EBS volume snapshots response."""
    DescribeSnapshotsResponse: Optional[DescribeSnapshotsResponse] = None

    class Config:
        extra = "allow"


# --- Main Input Schema ---

class IsBackupEnabledInput(BaseModel):
    """
    Expected input schema for the isbackupenabled transformation.

    This schema validates the API response structure containing:
    - dbBackups: RDS automated backups
    - dbManualSnapshots: RDS manual snapshots
    - volumeSnapshots: EBS volume snapshots
    """

    dbBackups: Optional[DBBackups] = Field(
        default=None,
        description="RDS automated backups from DescribeDBInstanceAutomatedBackups"
    )
    dbManualSnapshots: Optional[DBManualSnapshots] = Field(
        default=None,
        description="RDS manual snapshots from DescribeDBSnapshots"
    )
    volumeSnapshots: Optional[VolumeSnapshots] = Field(
        default=None,
        description="EBS volume snapshots from DescribeSnapshots"
    )

    class Config:
        extra = "allow"
