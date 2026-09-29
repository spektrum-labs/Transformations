"""Schema registry for this vendor's transformations."""

from .activeIntegrationsCount import ActiveIntegrationsCountInput
from .assetTriageBacklogCount import AssetTriageBacklogCountInput
from .certificateExpiringSoonCount import CertificateExpiringSoonCountInput
from .isASMEnabled import IsASMEnabledInput
from .isCloudAssetDiscoveryEnabled import IsCloudAssetDiscoveryEnabledInput
from .isContinuousDiscoveryEnabled import IsContinuousDiscoveryEnabledInput
from .isRiskPrioritizationTrue import IsRiskPrioritizationTrueInput
from .isSavedQueryMonitoringEnabled import IsSavedQueryMonitoringEnabledInput
from .isShadowITAssetTaggingEnabled import IsShadowITAssetTaggingEnabledInput
from .isSubsidiaryDiscoveryEnabled import IsSubsidiaryDiscoveryEnabledInput
from .isUnmanagedAssetDiscoveryEnabled import IsUnmanagedAssetDiscoveryEnabledInput
from .noCriticalFindings import NoCriticalFindingsInput
from .noHighFindings import NoHighFindingsInput

__all__ = [
    "ActiveIntegrationsCountInput",
    "AssetTriageBacklogCountInput",
    "CertificateExpiringSoonCountInput",
    "IsASMEnabledInput",
    "IsCloudAssetDiscoveryEnabledInput",
    "IsContinuousDiscoveryEnabledInput",
    "IsRiskPrioritizationTrueInput",
    "IsSavedQueryMonitoringEnabledInput",
    "IsShadowITAssetTaggingEnabledInput",
    "IsSubsidiaryDiscoveryEnabledInput",
    "IsUnmanagedAssetDiscoveryEnabledInput",
    "NoCriticalFindingsInput",
    "NoHighFindingsInput",
]
