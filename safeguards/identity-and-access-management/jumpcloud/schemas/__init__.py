"""Schema registry for this vendor's transformations."""

from .areConditionalAccessPoliciesConfigured import AreConditionalAccessPoliciesConfiguredInput
from .authTypesAllowed import AuthTypesAllowedInput
from .desktopAuthenticatorEnrollmentPercentage import DesktopAuthenticatorEnrollmentPercentageInput
from .hasAuthenticationLogAPIAccess import HasAuthenticationLogAPIAccessInput
from .inactiveMfaFactorsCount import InactiveMfaFactorsCountInput
from .isAdminMFAPhishingResistant import IsAdminMFAPhishingResistantInput
from .isAuditLoggingEnabled import IsAuditLoggingEnabledInput
from .isGroupMembershipChangeAudited import IsGroupMembershipChangeAuditedInput
from .isIAMLoggingEnabled import IsIAMLoggingEnabledInput
from .isIdentityProfileSyncEnabled import IsIdentityProfileSyncEnabledInput
from .isLifeCycleManagementEnabled import IsLifeCycleManagementEnabledInput
from .isMFAConfiguredForSecurityAdmins import IsMFAConfiguredForSecurityAdminsInput
from .isMFAEnabled import IsMFAEnabledInput
from .isMFAEnforced import IsMFAEnforcedInput
from .isMFAEnforcedForUsers import IsMFAEnforcedForUsersInput
from .isMFALoggingEnabled import IsMFALoggingEnabledInput
from .isSmsAuthenticationDisabled import IsSmsAuthenticationDisabledInput
from .isSSOEnabled import IsSSOEnabledInput
from .isStrongAuthRequired import IsStrongAuthRequiredInput
from .lockedOutUsersCount import LockedOutUsersCountInput
from .mfaDeviceEnrollmentPercentage import MfaDeviceEnrollmentPercentageInput
from .mfaEnforcementCoveragePercentage import MfaEnforcementCoveragePercentageInput
from .passwordOnlyAuthPolicyRulesCount import PasswordOnlyAuthPolicyRulesCountInput
from .relyingPartyTrustsWithoutAccessControlPolicyCount import RelyingPartyTrustsWithoutAccessControlPolicyCountInput
from .smsFactorEnabledUsersCount import SmsFactorEnabledUsersCountInput
from .suspendedUsersCount import SuspendedUsersCountInput
from .webAuthnCredentialAdoptionPercentage import WebAuthnCredentialAdoptionPercentageInput

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
