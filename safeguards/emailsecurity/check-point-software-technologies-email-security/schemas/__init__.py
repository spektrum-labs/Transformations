"""Schema registry for this vendor's transformations."""

from .isAccountTakeoverDetectionEnabled import IsAccountTakeoverDetectionEnabledInput
from .isAntiPhishingEnabled import IsAntiPhishingEnabledInput
from .isAntivirusVerdictEngineEnabled import IsAntivirusVerdictEngineEnabledInput
from .isCloudDataLeakPreventionEnabled import IsCloudDataLeakPreventionEnabledInput
from .isFlexibleSecurityEventQueryEnabled import IsFlexibleSecurityEventQueryEnabledInput
from .isImposterEmailDetectionEnabled import IsImposterEmailDetectionEnabledInput
from .isLinkedO365AccountActive import IsLinkedO365AccountActiveInput
from .isMaliciousClickBlockingEnabled import IsMaliciousClickBlockingEnabledInput
from .isPostDeliveryQuarantineEnabled import IsPostDeliveryQuarantineEnabledInput
from .isQuarantineRestoreWorkflowAutomated import IsQuarantineRestoreWorkflowAutomatedInput
from .isScopedAPIAuthTokenManaged import IsScopedAPIAuthTokenManagedInput
from .isShadowITDiscoveryEnabled import IsShadowITDiscoveryEnabledInput
from .isSingleActionMultiEntityRemediationEnabled import IsSingleActionMultiEntityRemediationEnabledInput
from .isSingleEntityForensicRetrievalEnabled import IsSingleEntityForensicRetrievalEnabledInput
from .isThreatInvestigationSweepEnabled import IsThreatInvestigationSweepEnabledInput
from .isThreatMitigationActionAPIEnabled import IsThreatMitigationActionAPIEnabledInput
from .isURLReputationBlockListEnforced import IsURLReputationBlockListEnforcedInput
from .messageMoveAuditTrailEnabled import MessageMoveAuditTrailEnabledInput
from .openQuarantinedMessagesCount import OpenQuarantinedMessagesCountInput

__all__ = [
    "IsAccountTakeoverDetectionEnabledInput",
    "IsAntiPhishingEnabledInput",
    "IsAntivirusVerdictEngineEnabledInput",
    "IsCloudDataLeakPreventionEnabledInput",
    "IsFlexibleSecurityEventQueryEnabledInput",
    "IsImposterEmailDetectionEnabledInput",
    "IsLinkedO365AccountActiveInput",
    "IsMaliciousClickBlockingEnabledInput",
    "IsPostDeliveryQuarantineEnabledInput",
    "IsQuarantineRestoreWorkflowAutomatedInput",
    "IsScopedAPIAuthTokenManagedInput",
    "IsShadowITDiscoveryEnabledInput",
    "IsSingleActionMultiEntityRemediationEnabledInput",
    "IsSingleEntityForensicRetrievalEnabledInput",
    "IsThreatInvestigationSweepEnabledInput",
    "IsThreatMitigationActionAPIEnabledInput",
    "IsURLReputationBlockListEnforcedInput",
    "MessageMoveAuditTrailEnabledInput",
    "OpenQuarantinedMessagesCountInput",
]
