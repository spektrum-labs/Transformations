from pydantic import BaseModel


class IsEPPLoggingEnabledOutput(BaseModel):
    isEPPLoggingEnabled: bool
    agentsWithEDRLogging: int
    agentsSampled: int
    totalAgents: int
