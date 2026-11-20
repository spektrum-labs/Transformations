"""Schema registry for this vendor's transformations."""

from .activeThreatIntelWatchlistCount import ActiveThreatIntelWatchlistCountInput
from .customDetectionRuleCount import CustomDetectionRuleCountInput
from .customFileFingerprintBlacklistCount import CustomFileFingerprintBlacklistCountInput
from .isApiAuditLoggingEnabled import IsApiAuditLoggingEnabledInput
from .isAuthEventCollectionEnabled import IsAuthEventCollectionEnabledInput
from .isRansomwareDetectionEnabled import IsRansomwareDetectionEnabledInput
from .isThreatIntelIOCLookupEnabled import IsThreatIntelIOCLookupEnabledInput

__all__ = [
    "ActiveThreatIntelWatchlistCountInput",
    "CustomDetectionRuleCountInput",
    "CustomFileFingerprintBlacklistCountInput",
    "IsApiAuditLoggingEnabledInput",
    "IsAuthEventCollectionEnabledInput",
    "IsRansomwareDetectionEnabledInput",
    "IsThreatIntelIOCLookupEnabledInput",
]
