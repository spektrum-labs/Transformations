from pydantic import BaseModel


class NumActiveDataConnectorsInput(BaseModel):
    """Input schema for the numActiveDataConnectors transformation."""

    class Config:
        extra = "allow"
