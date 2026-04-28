from pydantic import BaseModel


class IsEPPConfiguredOutput(BaseModel):
    isEPPConfigured: bool
    totalAgents: int
    protectModeAgents: int
    sampleSize: int
