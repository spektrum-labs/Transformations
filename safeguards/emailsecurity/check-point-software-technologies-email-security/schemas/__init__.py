"""Schema registry for this vendor's transformations."""

from .isAccountTakeoverDetectionEnabled import IsAccountTakeoverDetectionEnabledInput
from .isAttachmentSandboxDetonationEnabled import IsAttachmentSandboxDetonationEnabledInput
from .isCloudDataLeakPreventionEnabled import IsCloudDataLeakPreventionEnabledInput
from .isDKIMEnforced import IsDKIMEnforcedInput
from .isDMARCPolicyHonored import IsDMARCPolicyHonoredInput
from .isGlobalIntelligenceNetworkCorrelationEnabled import IsGlobalIntelligenceNetworkCorrelationEnabledInput
from .isLinkedO365AccountActive import IsLinkedO365AccountActiveInput
from .isMaliciousClickBlockingEnabled import IsMaliciousClickBlockingEnabledInput
from .isQuarantineRestoreWorkflowAutomated import IsQuarantineRestoreWorkflowAutomatedInput
from .isShadowITDiscoveryEnabled import IsShadowITDiscoveryEnabledInput
from .isSingleActionMultiEntityRemediationEnabled import IsSingleActionMultiEntityRemediationEnabledInput
from .isSingleEntityForensicRetrievalEnabled import IsSingleEntityForensicRetrievalEnabledInput
from .isThreatMitigationActionAPIEnabled import IsThreatMitigationActionAPIEnabledInput

__all__ = [
    "IsAccountTakeoverDetectionEnabledInput",
    "IsAttachmentSandboxDetonationEnabledInput",
    "IsCloudDataLeakPreventionEnabledInput",
    "IsDKIMEnforcedInput",
    "IsDMARCPolicyHonoredInput",
    "IsGlobalIntelligenceNetworkCorrelationEnabledInput",
    "IsLinkedO365AccountActiveInput",
    "IsMaliciousClickBlockingEnabledInput",
    "IsQuarantineRestoreWorkflowAutomatedInput",
    "IsShadowITDiscoveryEnabledInput",
    "IsSingleActionMultiEntityRemediationEnabledInput",
    "IsSingleEntityForensicRetrievalEnabledInput",
    "IsThreatMitigationActionAPIEnabledInput",
]
