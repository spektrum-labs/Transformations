"""Schema registry for this vendor's transformations."""

from .isBareMetalRecoveryEnabled import IsBareMetalRecoveryEnabledInput
from .isJobExecutionLogAccessible import IsJobExecutionLogAccessibleInput
from .isPrivateKeyEncryptionEnforced import IsPrivateKeyEncryptionEnforcedInput
from .isSubCompanyDataIsolationEnforced import IsSubCompanyDataIsolationEnforcedInput

__all__ = [
    "IsBareMetalRecoveryEnabledInput",
    "IsJobExecutionLogAccessibleInput",
    "IsPrivateKeyEncryptionEnforcedInput",
    "IsSubCompanyDataIsolationEnforcedInput",
]
