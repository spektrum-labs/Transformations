"""Schema registry for this vendor's transformations."""

from .exploitedFindingsCount import ExploitedFindingsCountInput
from .isASMEnabled import IsASMEnabledInput
from .isContinuousDiscoveryEnabled import IsContinuousDiscoveryEnabledInput
from .isRemediationTracked import IsRemediationTrackedInput
from .isRiskPrioritizationTrue import IsRiskPrioritizationTrueInput
from .isSubdomainTakeoverDetected import IsSubdomainTakeoverDetectedInput
from .isThreatIntelIntegrated import IsThreatIntelIntegratedInput
from .isUnmanagedAssetDiscoveryEnabled import IsUnmanagedAssetDiscoveryEnabledInput
from .noCriticalFindings import NoCriticalFindingsInput
from .noHighFindings import NoHighFindingsInput

__all__ = [
    "ExploitedFindingsCountInput",
    "IsASMEnabledInput",
    "IsContinuousDiscoveryEnabledInput",
    "IsRemediationTrackedInput",
    "IsRiskPrioritizationTrueInput",
    "IsSubdomainTakeoverDetectedInput",
    "IsThreatIntelIntegratedInput",
    "IsUnmanagedAssetDiscoveryEnabledInput",
    "NoCriticalFindingsInput",
    "NoHighFindingsInput",
]
