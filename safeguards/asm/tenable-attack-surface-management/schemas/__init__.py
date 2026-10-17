"""Schema registry for this vendor's transformations."""

from .certificateExpiringSoonCount import CertificateExpiringSoonCountInput
from .isASMEnabled import IsASMEnabledInput
from .isBusinessDivisionAttributionEnabled import IsBusinessDivisionAttributionEnabledInput
from .isRiskPrioritizationTrue import IsRiskPrioritizationTrueInput
from .isShadowITAssetTaggingEnabled import IsShadowITAssetTaggingEnabledInput
from .isUnmanagedAssetDiscoveryEnabled import IsUnmanagedAssetDiscoveryEnabledInput
from .noCriticalFindings import NoCriticalFindingsInput
from .noHighFindings import NoHighFindingsInput

__all__ = [
    "CertificateExpiringSoonCountInput",
    "IsASMEnabledInput",
    "IsBusinessDivisionAttributionEnabledInput",
    "IsRiskPrioritizationTrueInput",
    "IsShadowITAssetTaggingEnabledInput",
    "IsUnmanagedAssetDiscoveryEnabledInput",
    "NoCriticalFindingsInput",
    "NoHighFindingsInput",
]
