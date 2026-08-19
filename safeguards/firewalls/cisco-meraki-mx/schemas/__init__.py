"""Schema registry for this vendor's transformations."""

from .adminLockoutThresholdCount import AdminLockoutThresholdCountInput
from .confirmedLicensePurchased import ConfirmedLicensePurchasedInput
from .isAdminIdleTimeoutEnforced import IsAdminIdleTimeoutEnforcedInput
from .isApiKeyIpRestrictionEnabled import IsApiKeyIpRestrictionEnabledInput
from .isProgrammaticAccessEnabled import IsProgrammaticAccessEnabledInput
from .isSSOEnabled import IsSSOEnabledInput
from .isStrongPasswordPolicyEnforced import IsStrongPasswordPolicyEnforcedInput
from .isTwoFactorAuthEnforced import IsTwoFactorAuthEnforcedInput
from .vpnPeerReachablePercentage import VpnPeerReachablePercentageInput
from .vpnTunnelEstablished import VpnTunnelEstablishedInput

__all__ = [
    "AdminLockoutThresholdCountInput",
    "ConfirmedLicensePurchasedInput",
    "IsAdminIdleTimeoutEnforcedInput",
    "IsApiKeyIpRestrictionEnabledInput",
    "IsProgrammaticAccessEnabledInput",
    "IsSSOEnabledInput",
    "IsStrongPasswordPolicyEnforcedInput",
    "IsTwoFactorAuthEnforcedInput",
    "VpnPeerReachablePercentageInput",
    "VpnTunnelEstablishedInput",
]
