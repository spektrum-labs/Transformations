from pydantic import BaseModel
from typing import List


class IsEPPConfiguredOutput(BaseModel):
    isEPPConfigured: bool
    totalAgents: int
    activeAgents: int
    misconfiguredAgents: int
    misconfigurationReasons: List[str]
