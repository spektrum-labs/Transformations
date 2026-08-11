"""Schema registry for this vendor's transformations."""

from .isAntiPhishingEnabled import IsAntiPhishingEnabledInput
from .isEmailSecurityLoggingEnabled import IsEmailSecurityLoggingEnabledInput
from .isSafeAttachmentsEnabled import IsSafeAttachmentsEnabledInput
from .isSafeLinksEnabled import IsSafeLinksEnabledInput

__all__ = [
    "IsAntiPhishingEnabledInput",
    "IsEmailSecurityLoggingEnabledInput",
    "IsSafeAttachmentsEnabledInput",
    "IsSafeLinksEnabledInput",
]
