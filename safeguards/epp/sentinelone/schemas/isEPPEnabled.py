from pydantic import BaseModel
from typing import Optional


class IsEPPEnabledOutput(BaseModel):
    isEPPEnabled: bool
    totalAgents: int
    agentsInPageSample: int
    activeAgentsInSample: int
    decommissionedAgentsInSample: int
