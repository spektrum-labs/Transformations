"""Schema registry for this vendor's transformations."""

from .authTypesAllowed import AuthTypesAllowedInput
from .conditionalAccessPoliciesActive import ConditionalAccessPoliciesActiveInput
from .isAuditLoggingEnabled import IsAuditLoggingEnabledInput
from .isMFAConfiguredForSecurityAdmins import IsMFAConfiguredForSecurityAdminsInput
from .isMFAEnforcedForUsers import IsMFAEnforcedForUsersInput
from .isMFARequiredForRemoteAccess import IsMFARequiredForRemoteAccessInput
from .isStrongAuthRequired import IsStrongAuthRequiredInput
from .legacyAuthBlocked import LegacyAuthBlockedInput

__all__ = [
    "AuthTypesAllowedInput",
    "ConditionalAccessPoliciesActiveInput",
    "IsAuditLoggingEnabledInput",
    "IsMFAConfiguredForSecurityAdminsInput",
    "IsMFAEnforcedForUsersInput",
    "IsMFARequiredForRemoteAccessInput",
    "IsStrongAuthRequiredInput",
    "LegacyAuthBlockedInput",
]
