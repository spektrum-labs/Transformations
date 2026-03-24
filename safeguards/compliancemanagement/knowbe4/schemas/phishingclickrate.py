from typing import Optional
from pydantic import BaseModel


class PhishingclickrateInput(BaseModel):
    phish_prone_percentage: Optional[float] = None
