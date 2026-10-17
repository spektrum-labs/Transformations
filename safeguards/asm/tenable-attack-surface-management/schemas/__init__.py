"""Schema registry for this vendor's transformations."""

from .confirmedLicensePurchased import ConfirmedLicensePurchasedInput
from .isASMEnabled import IsASMEnabledInput
from .isBillableAssetTrackingEnabled import IsBillableAssetTrackingEnabledInput
from .isBusinessDivisionAttributionEnabled import IsBusinessDivisionAttributionEnabledInput
from .isRiskPrioritizationTrue import IsRiskPrioritizationTrueInput
from .isShadowITAssetTaggingEnabled import IsShadowITAssetTaggingEnabledInput
from .isUnmanagedAssetDiscoveryEnabled import IsUnmanagedAssetDiscoveryEnabledInput

__all__ = [
    "ConfirmedLicensePurchasedInput",
    "IsASMEnabledInput",
    "IsBillableAssetTrackingEnabledInput",
    "IsBusinessDivisionAttributionEnabledInput",
    "IsRiskPrioritizationTrueInput",
    "IsShadowITAssetTaggingEnabledInput",
    "IsUnmanagedAssetDiscoveryEnabledInput",
]
