from typing import Optional
from pydantic import BaseModel


class ConfirmedlicensepurchasedInput(BaseModel):
    subscription_level: Optional[str] = None
    subscription_end_date: Optional[str] = None
