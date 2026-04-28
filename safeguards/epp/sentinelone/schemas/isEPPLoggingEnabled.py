from pydantic import BaseModel

class IsEPPLoggingEnabledOutput(BaseModel):
    isEPPLoggingEnabled: bool
    agentsWithLoggingEnabled: int
    agentsWithoutLoggingEnabled: int
    totalAgents: int
