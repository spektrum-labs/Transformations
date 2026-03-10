"""Pydantic schemas for transformation inputs."""
from .confirmedlicensepurchased import ConfirmedlicensepurchasedInput
from .ismdrenabled import IsmdrennabledInput
from .isentitymonitoringactive import IsentitymonitoringactiveInput
from .isalertingenabled import IsalertingenabledInput
from .isauthorizedmodeenabled import IsauthorizedmodeenabledInput
from .istakedownserviceenabled import IstakedownserviceenabledInput
from .requiredcoveragepercentage import RequiredcoveragepercentageInput

__all__ = [
    "ConfirmedlicensepurchasedInput",
    "IsmdrennabledInput",
    "IsentitymonitoringactiveInput",
    "IsalertingenabledInput",
    "IsauthorizedmodeenabledInput",
    "IstakedownserviceenabledInput",
    "RequiredcoveragepercentageInput",
]
