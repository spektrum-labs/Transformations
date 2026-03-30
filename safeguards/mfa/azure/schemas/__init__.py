"""Pydantic schemas for transformation inputs."""

from .auth_types_allowed import AuthTypesAllowedInput
from .confirmedlicensepurchased import ConfirmedlicensepurchasedInput
from .confirmlicensepurchased import ConfirmlicensepurchasedInput
from .confirmpasswordpolicyenforced import ConfirmpasswordpolicyenforcedInput
from .is_mfa_logging_enabled import IsMfaLoggingEnabledInput
from .isauditloggingenabled import IsauditloggingenabledInput
from .islifecyclemanagementenabled import IslifecyclemanagementenabledInput
from .ismfaenabled import IsmfaenabledInput
from .ismfaenforcedforusers import IsmfaenforcedforusersInput
from .ispamenabled import IspamenabledInput
from .isrbacimplemented import IsrbacimplementedInput
from .isstrongauthrequired import IsstrongauthrequiredInput
from .mfa_transform import MfaTransformInput
from .ismfarequiredforremoteaccess import IsmfarequiredforremoteaccessInput
from .ismfarequiredforcloudapps import IsmfarequiredforcloudappsInput
from .conditionalaccesspoliciesactive import ConditionalaccesspoliciesactiveInput
from .legacyauthblocked import LegacyauthblockedInput
from .isrdpprotected import IsrdpprotectedInput

__all__ = [
    "AuthTypesAllowedInput",
    "ConfirmedlicensepurchasedInput",
    "ConfirmlicensepurchasedInput",
    "ConfirmpasswordpolicyenforcedInput",
    "IsMfaLoggingEnabledInput",
    "IsauditloggingenabledInput",
    "IslifecyclemanagementenabledInput",
    "IsmfaenabledInput",
    "IsmfaenforcedforusersInput",
    "IspamenabledInput",
    "IsrbacimplementedInput",
    "IsstrongauthrequiredInput",
    "MfaTransformInput",
    "IsmfarequiredforremoteaccessInput",
    "IsmfarequiredforcloudappsInput",
    "ConditionalaccesspoliciesactiveInput",
    "LegacyauthblockedInput",
    "IsrdpprotectedInput",
]
