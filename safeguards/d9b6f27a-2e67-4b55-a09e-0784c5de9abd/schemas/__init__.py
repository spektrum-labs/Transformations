"""Pydantic schemas for transformation inputs."""

from .areaccessreviewsconfigured import AreaccessreviewsconfiguredInput
from .areconditionalaccesspoliciesconfigured import AreconditionalaccesspoliciesconfiguredInput
from .auth_types_allowed import AuthTypesAllowedInput
from .confirmedlicensepurchased import ConfirmedlicensepurchasedInput
from .confirmpasswordpolicyenforced import ConfirmpasswordpolicyenforcedInput
from .is_mfa_logging_enabled import IsMfaLoggingEnabledInput
from .isadminauditloggingenabled import IsadminauditloggingenabledInput
from .isadminmfaphishingresistant import IsadminmfaphishingresistantInput
from .isauditloggingenabled import IsauditloggingenabledInput
from .isidentityprotectionenabled import IsidentityprotectionenabledInput
from .islifecyclemanagementenabled import IslifecyclemanagementenabledInput
from .ismailboxauditloggingenabled import IsmailboxauditloggingenabledInput
from .ismfaconfiguredforsecurityadmins import IsmfaconfiguredforsecurityadminsInput
from .ismfaenabled import IsmfaenabledInput
from .ismfaenforcedforusers import IsmfaenforcedforusersInput
from .ispamenabled import IspamenabledInput
from .isprivilegedidentitymanagementenabled import IsprivilegedidentitymanagementenabledInput
from .isrbacimplemented import IsrbacimplementedInput
from .issecuritycenterintegrationenabled import IssecuritycenterintegrationenabledInput
from .isstrongauthrequired import IsstrongauthrequiredInput
from .isunifiedauditloggingenabled import IsunifiedauditloggingenabledInput
from .mfa_transform import MfaTransformInput

__all__ = [
    "AreaccessreviewsconfiguredInput",
    "AreconditionalaccesspoliciesconfiguredInput",
    "AuthTypesAllowedInput",
    "ConfirmedlicensepurchasedInput",
    "ConfirmpasswordpolicyenforcedInput",
    "IsMfaLoggingEnabledInput",
    "IsadminauditloggingenabledInput",
    "IsadminmfaphishingresistantInput",
    "IsauditloggingenabledInput",
    "IsidentityprotectionenabledInput",
    "IslifecyclemanagementenabledInput",
    "IsmailboxauditloggingenabledInput",
    "IsmfaconfiguredforsecurityadminsInput",
    "IsmfaenabledInput",
    "IsmfaenforcedforusersInput",
    "IspamenabledInput",
    "IsprivilegedidentitymanagementenabledInput",
    "IsrbacimplementedInput",
    "IssecuritycenterintegrationenabledInput",
    "IsstrongauthrequiredInput",
    "IsunifiedauditloggingenabledInput",
    "MfaTransformInput",
]
