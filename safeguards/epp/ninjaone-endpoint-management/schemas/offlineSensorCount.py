from pydantic import BaseModel


class OfflineSensorCountInput(BaseModel):
    """Input schema for the offlineSensorCount transformation.

    Accepts the getDevicesDetailed response shape, which may arrive as either
    a canonical list-of-records under 'data', a columnar/parallel-array
    payload (id/offline/organizationId as parallel lists), or a bare list.
    Kept permissive since NinjaOne's public API surface for this endpoint
    is not fully pinned down in public docs.
    """

    class Config:
        extra = "allow"
