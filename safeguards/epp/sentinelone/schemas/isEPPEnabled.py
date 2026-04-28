from pydantic import BaseModel


class IsEPPEnabledOutput(BaseModel):
    isEPPEnabled: bool
    totalAgents: int
    agentsInPage: int
