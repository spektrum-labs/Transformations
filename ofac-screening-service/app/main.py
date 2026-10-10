"""FastAPI entrypoint for the OFAC screening service.

* ``lifespan`` startup loads the promoted advanced list into a
  :class:`~app.matcher.PartyStore` (which hot-reloads on mtime change — no
  restart when the hourly sync promotes new data).
* ``POST /screen`` runs fuzzy name matching and emits an L4 receipt +
  evidence item. A ``potential_match`` is surfaced for human adjudication and is
  never reported as an auto-confirmed hit.
"""

from __future__ import annotations

import os
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import FastAPI
from pydantic import BaseModel, Field

from .matcher import DEFAULT_MATCH_THRESHOLD, PartyStore, screen_name
from .receipts import build_evidence_item, build_receipt, receipt_to_html

def _data_dir() -> str:
    return os.environ.get("OFAC_DATA_DIR", "data")


def _live_file() -> str:
    return os.environ.get("OFAC_LIVE_FILE", "sdn_advanced.xml")


class ScreenRequest(BaseModel):
    name: str = Field(..., description="Name to screen against the OFAC lists")
    entity_type: Optional[str] = Field(
        None, description="Optional filter: Individual | Entity | Vessel | Aircraft"
    )
    match_threshold: float = Field(
        DEFAULT_MATCH_THRESHOLD, description="Score (0-100) at/above which a name is a potential match"
    )


def _store_for_app() -> PartyStore:
    live_path = os.path.join(_data_dir(), _live_file())
    return PartyStore(data_path=live_path)


@asynccontextmanager
async def lifespan(app: FastAPI):
    store = _store_for_app()
    # Touch the store so the initial file (if present) is loaded eagerly.
    _ = store.parties
    app.state.store = store
    yield


app = FastAPI(title="OFAC Screening Service", version="1.0.0", lifespan=lifespan)


def run_screen(store: PartyStore, req: ScreenRequest, *, created_at: str | None = None) -> dict[str, Any]:
    """Pure screening routine — shared by the route and by tests."""
    matches = screen_name(
        req.name,
        store.parties,
        entity_type=req.entity_type,
        match_threshold=req.match_threshold,
    )
    potential_matches = [
        {
            "fixed_ref": m.fixed_ref,
            "entity_type": m.entity_type,
            "primary_name": m.primary_name,
            "matched_name": m.matched_name,
            "matched_on_primary": m.matched_on_primary,
            "score": m.score,
        }
        for m in matches
    ]
    status = "potential_match" if potential_matches else "clear"
    receipt = build_receipt(
        query_name=req.name,
        entity_type=req.entity_type,
        status=status,
        match_threshold=req.match_threshold,
        data_version=store.data_version,
        potential_matches=potential_matches,
        created_at=created_at,
    )
    return {
        "status": status,
        "is_clear": status == "clear",
        "requires_adjudication": status == "potential_match",
        "potential_matches": potential_matches,
        "receipt": receipt,
        "receipt_html": receipt_to_html(receipt),
        "evidence_item": build_evidence_item(receipt),
    }


@app.get("/health")
async def health() -> dict[str, Any]:
    store: PartyStore = app.state.store
    return {"status": "ok", "record_count": len(store.parties), "data_version": store.data_version}


@app.post("/screen")
async def screen(req: ScreenRequest) -> dict[str, Any]:
    store: PartyStore = app.state.store
    created_at = datetime.now(timezone.utc).isoformat()
    return run_screen(store, req, created_at=created_at)
