"""Pydantic schemas for transformation inputs."""

from .confirmedlicensepurchased import ConfirmedlicensepurchasedInput
from .epp_transform import EppTransformInput
from .isbehavioralmonitoringvalid import IsbehavioralmonitoringvalidInput
from .isidpenabled import IsidpenabledInput
from .ispatchmanagementenabled import IspatchmanagementenabledInput
from .isremovablemediacontrolled import IsremovablemediacontrolledInput

__all__ = [
    "ConfirmedlicensepurchasedInput",
    "EppTransformInput",
    "IsbehavioralmonitoringvalidInput",
    "IsidpenabledInput",
    "IspatchmanagementenabledInput",
    "IsremovablemediacontrolledInput",
]
