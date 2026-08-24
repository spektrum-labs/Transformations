"""Pydantic schemas for Cisco Umbrella (Network Security) transformation inputs."""

from .isswgenabled import IsswgenabledInput
from .hasnetworktunnelsconfigured import HasnetworktunnelsconfiguredInput
from .iscontinuousdiscoveryenabled import IscontinuousdiscoveryenabledInput
from .openhighriskappscount import OpenhighriskappscountInput
from .maliciousdomainblockrate import MaliciousdomainblockrateInput

__all__ = [
    "IsswgenabledInput",
    "HasnetworktunnelsconfiguredInput",
    "IscontinuousdiscoveryenabledInput",
    "OpenhighriskappscountInput",
    "MaliciousdomainblockrateInput",
]
