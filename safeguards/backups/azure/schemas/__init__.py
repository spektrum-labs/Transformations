"""Pydantic schemas for Azure Backup transformation inputs."""

from .backupfrequency import BackupfrequencyInput
from .confirmedlicensepurchased import ConfirmedlicensepurchasedInput
from .is_backup_enabled_for_critical_systems import IsBackupEnabledForCriticalSystemsInput
from .is_backup_encrypted import IsBackupEncryptedInput
from .is_backup_immutable import IsBackupImmutableInput
from .is_backup_logging_enabled import IsBackupLoggingEnabledInput
from .is_backup_tested import IsBackupTestedInput
from .is_backup_types_scheduled import IsBackupTypesScheduledInput
from .isbackupenabled import IsbackupenabledInput
from .isgeoredundant import IsgeoredundantInput
from .issamlenforced import IssamlenforcedInput
from .lastsuccessfulbackupage import LastsuccessfulbackupageInput
from .recoverytestcompleted import RecoverytestcompletedInput

__all__ = [
    "BackupfrequencyInput",
    "ConfirmedlicensepurchasedInput",
    "IsBackupEnabledForCriticalSystemsInput",
    "IsBackupEncryptedInput",
    "IsBackupImmutableInput",
    "IsBackupLoggingEnabledInput",
    "IsBackupTestedInput",
    "IsBackupTypesScheduledInput",
    "IsbackupenabledInput",
    "IsgeoredundantInput",
    "IssamlenforcedInput",
    "LastsuccessfulbackupageInput",
    "RecoverytestcompletedInput",
]
