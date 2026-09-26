"""Schema registry for this vendor's transformations."""

from .bypassStatusUsersCount import BypassStatusUsersCountInput
from .desktopAuthenticatorEnrollmentPercentage import DesktopAuthenticatorEnrollmentPercentageInput
from .hasAuthenticationLogAPIAccess import HasAuthenticationLogAPIAccessInput
from .hasEmergencyAccessCodeAPIAccess import HasEmergencyAccessCodeAPIAccessInput
from .hasFIDOAuthenticatorManagementAPIAccess import HasFIDOAuthenticatorManagementAPIAccessInput
from .lockedOutUsersCount import LockedOutUsersCountInput
from .mfaDeviceEnrollmentPercentage import MfaDeviceEnrollmentPercentageInput
from .smsFactorEnabledUsersCount import SmsFactorEnabledUsersCountInput
from .superAdminMfaEnrollmentPercentage import SuperAdminMfaEnrollmentPercentageInput
from .webAuthnCredentialAdoptionPercentage import WebAuthnCredentialAdoptionPercentageInput

__all__ = [
    "BypassStatusUsersCountInput",
    "DesktopAuthenticatorEnrollmentPercentageInput",
    "HasAuthenticationLogAPIAccessInput",
    "HasEmergencyAccessCodeAPIAccessInput",
    "HasFIDOAuthenticatorManagementAPIAccessInput",
    "LockedOutUsersCountInput",
    "MfaDeviceEnrollmentPercentageInput",
    "SmsFactorEnabledUsersCountInput",
    "SuperAdminMfaEnrollmentPercentageInput",
    "WebAuthnCredentialAdoptionPercentageInput",
]
