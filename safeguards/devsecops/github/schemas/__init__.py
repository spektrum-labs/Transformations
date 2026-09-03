"""Schema registry for this vendor's transformations."""

from .isAdvancedSecurityEnabled import IsAdvancedSecurityEnabledInput
from .isDependabotAlertsEnabled import IsDependabotAlertsEnabledInput
from .isSecretScanningPushProtectionEnabled import IsSecretScanningPushProtectionEnabledInput

__all__ = [
    "IsAdvancedSecurityEnabledInput",
    "IsDependabotAlertsEnabledInput",
    "IsSecretScanningPushProtectionEnabledInput",
]
