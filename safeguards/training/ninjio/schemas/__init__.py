"""Pydantic schemas for transformation inputs."""
from .confirmedlicensepurchased import ConfirmedlicensepurchasedInput
from .istrainingenabled import IstrainingenabledInput
from .isphishingsimulationenabled import IsphishingsimulationenabledInput
from .iscompletionrateacceptable import IscompletionrateacceptableInput
from .isreportingenabled import IsreportingenabledInput
from .hasactiveemployees import HasactiveemployeesInput
from .isphishingremediationconfigured import IsphishingremediationconfiguredInput

__all__ = [
    "ConfirmedlicensepurchasedInput",
    "IstrainingenabledInput",
    "IsphishingsimulationenabledInput",
    "IscompletionrateacceptableInput",
    "IsreportingenabledInput",
    "HasactiveemployeesInput",
    "IsphishingremediationconfiguredInput",
]
