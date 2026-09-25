"""Schema registry for this vendor's transformations."""

from .isMFAEnforcedForUsers import IsMFAEnforcedForUsersInput
from .isSuperAdminMfaFullyEnforced import IsSuperAdminMfaFullyEnforcedInput
from .mfaExemptUserAccountsCount import MfaExemptUserAccountsCountInput
from .superAdminAccountsWithoutMfaCount import SuperAdminAccountsWithoutMfaCountInput
from .workspaceUserMfaEnforcementPercentage import WorkspaceUserMfaEnforcementPercentageInput
from .workspaceUserMfaEnrollmentPercentage import WorkspaceUserMfaEnrollmentPercentageInput

__all__ = [
    "IsMFAEnforcedForUsersInput",
    "IsSuperAdminMfaFullyEnforcedInput",
    "MfaExemptUserAccountsCountInput",
    "SuperAdminAccountsWithoutMfaCountInput",
    "WorkspaceUserMfaEnforcementPercentageInput",
    "WorkspaceUserMfaEnrollmentPercentageInput",
]
