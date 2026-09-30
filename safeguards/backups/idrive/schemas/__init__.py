"""Schema registry for this vendor's transformations."""

from .backupSuccessRatePercentage import BackupSuccessRatePercentageInput
from .failedBackupJobsCount import FailedBackupJobsCountInput
from .isBackupEnabled import IsBackupEnabledInput
from .isBackupEncrypted import IsBackupEncryptedInput
from .isBackupFailureAlertRecipientConfigured import IsBackupFailureAlertRecipientConfiguredInput
from .isBackupTypesScheduled import IsBackupTypesScheduledInput
from .isDesktopAppStatusRestricted import IsDesktopAppStatusRestrictedInput
from .isEncryptionRequiredFlagSet import IsEncryptionRequiredFlagSetInput
from .isForeverIncrementalBackupEnabled import IsForeverIncrementalBackupEnabledInput
from .isHybridBackupDestinationConfigured import IsHybridBackupDestinationConfiguredInput
from .isMissedScheduledBackupAutoResumeEnabled import IsMissedScheduledBackupAutoResumeEnabledInput
from .isPolicyFailureNotificationConfigured import IsPolicyFailureNotificationConfiguredInput
from .isPrivateEncryptionKeyEnabled import IsPrivateEncryptionKeyEnabledInput
from .unprotectedResourcesCount import UnprotectedResourcesCountInput

__all__ = [
    "BackupSuccessRatePercentageInput",
    "FailedBackupJobsCountInput",
    "IsBackupEnabledInput",
    "IsBackupEncryptedInput",
    "IsBackupFailureAlertRecipientConfiguredInput",
    "IsBackupTypesScheduledInput",
    "IsDesktopAppStatusRestrictedInput",
    "IsEncryptionRequiredFlagSetInput",
    "IsForeverIncrementalBackupEnabledInput",
    "IsHybridBackupDestinationConfiguredInput",
    "IsMissedScheduledBackupAutoResumeEnabledInput",
    "IsPolicyFailureNotificationConfiguredInput",
    "IsPrivateEncryptionKeyEnabledInput",
    "UnprotectedResourcesCountInput",
]
