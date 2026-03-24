"""Pydantic schemas for transformation inputs."""

from .confirmedlicensepurchased import ConfirmedlicensepurchasedInput
from .epp_transform import EppTransformInput
from .hardenedbaselinecompliance import HardenedbaselinecomplianceInput
from .isbehavioralmonitoringvalid import IsbehavioralmonitoringvalidInput
from .isidpenabled import IsidpenabledInput
from .ispatchmanagementenabled import IspatchmanagementenabledInput
from .isrealtimeprotectionenabled import IsrealtimeprotectionenabledInput
from .isremovablemediacontrolled import IsremovablemediacontrolledInput
from .istamperprotectionenabled import IstamperprotectionenabledInput
from .requiredcoveragepercentage import RequiredcoveragepercentageInput
from .servercoveragepercentage import ServercoveragepercentageInput
from .totalendpointcount import TotalendpointcountInput
from .totalservercount import TotalservercountInput

__all__ = [
    "ConfirmedlicensepurchasedInput",
    "EppTransformInput",
    "HardenedbaselinecomplianceInput",
    "IsbehavioralmonitoringvalidInput",
    "IsidpenabledInput",
    "IspatchmanagementenabledInput",
    "IsrealtimeprotectionenabledInput",
    "IsremovablemediacontrolledInput",
    "IstamperprotectionenabledInput",
    "RequiredcoveragepercentageInput",
    "ServercoveragepercentageInput",
    "TotalendpointcountInput",
    "TotalservercountInput",
]
