"""Schema registry for this vendor's transformations."""

from .isAccountTakeoverDetectionEnabled import IsAccountTakeoverDetectionEnabledInput
from .isAntivirusVerdictEngineEnabled import IsAntivirusVerdictEngineEnabledInput
from .isAttachmentSandboxDetonationEnabled import IsAttachmentSandboxDetonationEnabledInput
from .isClickTimeURLRewriteEnabled import IsClickTimeURLRewriteEnabledInput
from .isCloudDataLeakPreventionEnabled import IsCloudDataLeakPreventionEnabledInput
from .isDKIMEnforced import IsDKIMEnforcedInput
from .isDMARCPolicyHonored import IsDMARCPolicyHonoredInput
from .isFlexibleSecurityEventQueryEnabled import IsFlexibleSecurityEventQueryEnabledInput
from .isGlobalIntelligenceNetworkCorrelationEnabled import IsGlobalIntelligenceNetworkCorrelationEnabledInput
from .isImposterEmailDetectionEnabled import IsImposterEmailDetectionEnabledInput
from .isLinkedO365AccountActive import IsLinkedO365AccountActiveInput
from .isMaliciousClickBlockingEnabled import IsMaliciousClickBlockingEnabledInput
from .isPostDeliveryQuarantineEnabled import IsPostDeliveryQuarantineEnabledInput
from .isQuarantineRestoreWorkflowAutomated import IsQuarantineRestoreWorkflowAutomatedInput
from .isSPFEnforced import IsSPFEnforcedInput
from .isShadowITDiscoveryEnabled import IsShadowITDiscoveryEnabledInput
from .isSingleActionMultiEntityRemediationEnabled import IsSingleActionMultiEntityRemediationEnabledInput
from .isSingleEntityForensicRetrievalEnabled import IsSingleEntityForensicRetrievalEnabledInput
from .isThreatInvestigationSweepEnabled import IsThreatInvestigationSweepEnabledInput
from .isThreatMitigationActionAPIEnabled import IsThreatMitigationActionAPIEnabledInput
from .isURLReputationBlockListEnforced import IsURLReputationBlockListEnforcedInput
from .messageMoveAuditTrailEnabled import MessageMoveAuditTrailEnabledInput
from .openQuarantinedMessagesCount import OpenQuarantinedMessagesCountInput
from .unverifiedAllowPolicyCount import UnverifiedAllowPolicyCountInput

__all__ = [
    "IsAccountTakeoverDetectionEnabledInput",
    "IsAntivirusVerdictEngineEnabledInput",
    "IsAttachmentSandboxDetonationEnabledInput",
    "IsClickTimeURLRewriteEnabledInput",
    "IsCloudDataLeakPreventionEnabledInput",
    "IsDKIMEnforcedInput",
    "IsDMARCPolicyHonoredInput",
    "IsFlexibleSecurityEventQueryEnabledInput",
    "IsGlobalIntelligenceNetworkCorrelationEnabledInput",
    "IsImposterEmailDetectionEnabledInput",
    "IsLinkedO365AccountActiveInput",
    "IsMaliciousClickBlockingEnabledInput",
    "IsPostDeliveryQuarantineEnabledInput",
    "IsQuarantineRestoreWorkflowAutomatedInput",
    "IsSPFEnforcedInput",
    "IsShadowITDiscoveryEnabledInput",
    "IsSingleActionMultiEntityRemediationEnabledInput",
    "IsSingleEntityForensicRetrievalEnabledInput",
    "IsThreatInvestigationSweepEnabledInput",
    "IsThreatMitigationActionAPIEnabledInput",
    "IsURLReputationBlockListEnforcedInput",
    "MessageMoveAuditTrailEnabledInput",
    "OpenQuarantinedMessagesCountInput",
    "UnverifiedAllowPolicyCountInput",
]
