"""Schema for is_backup_logging_enabled transformation input."""

from .isbackupenabled import IsBackupEnabledInput


class IsBackupLoggingEnabledInput(IsBackupEnabledInput):
    """
    Expected input schema for the is_backup_logging_enabled transformation.

    This schema shares the same structure as IsBackupEnabledInput since it
    processes the same AWS backup data (dbBackups, dbManualSnapshots, volumeSnapshots).
    """
    pass
