"""Schema for is_backup_types_scheduled transformation input."""

from .isbackupenabled import IsBackupEnabledInput


class IsBackupTypesScheduledInput(IsBackupEnabledInput):
    """
    Expected input schema for the is_backup_types_scheduled transformation.

    This schema shares the same structure as IsBackupEnabledInput since it
    processes the same AWS backup data (dbBackups, dbManualSnapshots, volumeSnapshots).
    """
    pass
