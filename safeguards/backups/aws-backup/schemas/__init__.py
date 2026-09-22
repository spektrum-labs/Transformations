"""Schema registry for this vendor's transformations."""

from .isAirGappedStorageEnabled import IsAirGappedStorageEnabledInput
from .isBackupEnabled import IsBackupEnabledInput
from .isBackupVaultLockGovernanceModeEnabled import IsBackupVaultLockGovernanceModeEnabledInput
from .isCloudBackupConfigured import IsCloudBackupConfiguredInput
from .isDataLockComplianceModeEnabled import IsDataLockComplianceModeEnabledInput
from .isInfiniteCloudRetentionEnabled import IsInfiniteCloudRetentionEnabledInput
from .isMinimumRetentionLockConfigured import IsMinimumRetentionLockConfiguredInput
from .isReadOnlySnapshotEnforced import IsReadOnlySnapshotEnforcedInput
from .isVaultManagedKMSEnabled import IsVaultManagedKMSEnabledInput
from .vaultRegionCount import VaultRegionCountInput

__all__ = [
    "IsAirGappedStorageEnabledInput",
    "IsBackupEnabledInput",
    "IsBackupVaultLockGovernanceModeEnabledInput",
    "IsCloudBackupConfiguredInput",
    "IsDataLockComplianceModeEnabledInput",
    "IsInfiniteCloudRetentionEnabledInput",
    "IsMinimumRetentionLockConfiguredInput",
    "IsReadOnlySnapshotEnforcedInput",
    "IsVaultManagedKMSEnabledInput",
    "VaultRegionCountInput",
]
