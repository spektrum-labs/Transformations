from pydantic import BaseModel


class IsEPPEnabledOutput(BaseModel):
    isEPPEnabled: bool
    totalAgents: int
    activeAgentsInPage: int
