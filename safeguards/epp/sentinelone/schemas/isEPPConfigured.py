from pydantic import BaseModel


class IsEPPConfiguredOutput(BaseModel):
    isEPPConfigured: bool
    totalAgents: int
    protectModeCount: int
    detectModeCount: int
