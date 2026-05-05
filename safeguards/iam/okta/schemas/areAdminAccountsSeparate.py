from pydantic import BaseModel
from typing import Any, Dict, List, Optional


class AreAdminAccountsSeparateInput(BaseModel):
    """Input schema for the areAdminAccountsSeparate transformation.

    The listUsers endpoint returns a JSON array of user objects. Each object
    contains an 'id', 'status', and 'profile' dict with 'login', 'email',
    'firstName', 'lastName', and 'displayName' fields.
    """

    class Config:
        extra = "allow"
