"""Pydantic schemas for ManageEngine Endpoint Central EPP transformation inputs."""
from .confirmedlicensepurchased import ConfirmedlicensepurchasedInput
from .isedrdeployed import IsedrdeployedInput
from .iseppdeployed import IseppdeployedInput
from .iseppmisconfigured import IseppmisconfiguredInput
from .ispatchmanagementenabled import IspatchmanagementenabledInput
from .ispatchmanagementvalid import IspatchmanagementvalidInput
from .isremovablemediacontrolled import IsremovablemediacontrolledInput
from .isbehavioralmonitoringvalid import IsbehavioralmonitoringvalidInput

__all__ = [
    "ConfirmedlicensepurchasedInput",
    "IsedrdeployedInput",
    "IseppdeployedInput",
    "IseppmisconfiguredInput",
    "IspatchmanagementenabledInput",
    "IspatchmanagementvalidInput",
    "IsremovablemediacontrolledInput",
    "IsbehavioralmonitoringvalidInput",
]
