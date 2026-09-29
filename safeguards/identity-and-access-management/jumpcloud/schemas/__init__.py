"""Schema registry for this vendor's transformations."""

from .areConditionalAccessPoliciesConfigured import AreConditionalAccessPoliciesConfiguredInput
from
from .desktopAuthenticatorEnrollmentPercentage import DesktopAuthenticatorEnrollmentPercentageInput
from
from .hasAuthenticationLogAPIAccess import HasAuthenticationLogAPIAccessInput
from .isAdminMFAPhishingResistant import IsAdminMFAPhishingResistantInput
from
from .isAuditLoggingEnabled import IsAuditLoggingEnabledInput
from .isGroupMembershipChangeAudited import IsGroupMembershipChangeAuditedInput
from .isIAMLoggingEnabled import IsIAMLoggingEnabledInput
from .isLifeCycleManagementEnabled import IsLifeCycleManagementEnabledInput
from
from .isMFAEnabled import IsMFAEnabledInput
from
from .isMFAEnforcedForUsers import IsMFAEnforcedForUsersInput
from
from .isMFALoggingEnabled import IsMFALoggingEnabledInput
from .isSmsAuthenticationDisabled import IsSmsAuthenticationDisabledInput
from
from .lockedOutUsersCount import LockedOutUsersCountInput
from
from .mfaEnforcementCoveragePercentage import MfaEnforcementCoveragePercentageInput
from
from .relyingPartyTrustsWithoutAccessControlPolicyCount import RelyingPartyTrustsWithoutAccessControlPolicyCountInput
from
from .suspendedUsersCount import SuspendedUsersCountInput
from

__all__ = [
    "AreConditionalAccessPoliciesConfiguredInput",
    "AuthTypesAllowedInput",
    "DesktopAuthenticatorEnrollmentPercentageInput",
    "HasAuthenticationLogAPIAccessInput",
    "InactiveMfaFactorsCountInput",
    "IsAdminMFAPhishingResistantInput",
    "IsAuditLoggingEnabledInput",
    "IsGroupMembershipChangeAuditedInput",
    "IsIAMLoggingEnabledInput",
    "IsIdentityProfileSyncEnabledInput",
    "IsLifeCycleManagementEnabledInput",
    "IsMFAConfiguredForSecurityAdminsInput",
    "IsMFAEnabledInput",
    "IsMFAEnforcedForUsersInput",
    "IsMFAEnforcedInput",
    "IsMFALoggingEnabledInput",
    "IsSSOEnabledInput",
    "IsSmsAuthenticationDisabledInput",
    "IsStrongAuthRequiredInput",
    "LockedOutUsersCountInput",
    "MfaDeviceEnrollmentPercentageInput",
    "MfaEnforcementCoveragePercentageInput",
    "PasswordOnlyAuthPolicyRulesCountInput",
    "RelyingPartyTrustsWithoutAccessControlPolicyCountInput",
    "SmsFactorEnabledUsersCountInput",
    "SuspendedUsersCountInput",
    "WebAuthnCredentialAdoptionPercentageInput",
]
