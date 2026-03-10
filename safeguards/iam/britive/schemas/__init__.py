"""Pydantic schemas for transformation inputs."""
from .confirmedlicensepurchased import ConfirmedlicensepurchasedInput
from .issamlenforced import IssamlenforcedInput
from .ismfaenabledforidentityprovider import IsmfaenabledforidentityproviderInput
from .isjitaccessenabled import IsjitaccessenabledInput
from .iszerostandingprivilegesenabled import IszerostandingprivilegesenabledInput
from .isapprovalworkflowconfigured import IsapprovalworkflowconfiguredInput
from .isauditloggingenabled import IsauditloggingenabledInput
from .areadminaccountsseparate import AreadminaccountsseparateInput

__all__ = [
    "ConfirmedlicensepurchasedInput",
    "IssamlenforcedInput",
    "IsmfaenabledforidentityproviderInput",
    "IsjitaccessenabledInput",
    "IszerostandingprivilegesenabledInput",
    "IsapprovalworkflowconfiguredInput",
    "IsauditloggingenabledInput",
    "AreadminaccountsseparateInput",
]
