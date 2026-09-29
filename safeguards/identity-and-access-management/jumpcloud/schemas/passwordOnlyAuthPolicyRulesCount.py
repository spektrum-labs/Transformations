from pydantic import BaseModel


class PasswordOnlyAuthPolicyRulesCountInput(BaseModel):
    """Input schema for the passwordOnlyAuthPolicyRulesCount transformation."""

    class Config:
        extra = "allow"
