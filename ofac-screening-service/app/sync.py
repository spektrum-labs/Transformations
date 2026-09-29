"""Hourly sync of the OFAC advanced XML exports.

For each source the sync:

1. Issues a **conditional GET** (``If-None-Match`` / ``If-Modified-Since``) and
   skips unchanged data (HTTP 304).
2. Computes a **sha256 fingerprint** and skips promotion if the bytes are
   byte-identical to what is already live.
3. Writes to a **temp file** and validates it *before* going live: it must parse
   as advanced XML and contain at least ``min_records`` parties. Only then is it
   atomically promoted with :func:`os.replace`.
4. Archives a **timestamped** copy and writes a per-fetch **provenance manifest**.

Downloading the real ~100 MB exports is avoided in tests by injecting a
``fetcher`` callable.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from dataclasses import asdict, dataclass
from typing import Callable

from .parser import parse_advanced

SDN_ADVANCED_URL = "https://sanctionslistservice.ofac.treas.gov/api/download/sdn_advanced.xml"
CONS_ADVANCED_URL = "https://sanctionslistservice.ofac.treas.gov/api/download/cons_advanced.xml"

DEFAULT_MIN_RECORDS = 1


@dataclass
class FetchResult:
    """Outcome of a conditional GET."""

    status: int  # 200 (new data), 304 (unchanged), or other
    content: bytes | None = None
    etag: str | None = None
    last_modified: str | None = None


# A fetcher takes (url, etag, last_modified) and returns a FetchResult.
Fetcher = Callable[[str, str | None, str | None], FetchResult]


@dataclass
class SyncOutcome:
    source: str
    result: str  # "promoted" | "unchanged" | "not-modified" | "rejected" | "error"
    record_count: int = 0
    sha256: str | None = None
    detail: str = ""


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _read_cache_meta(meta_path: str) -> dict:
    if os.path.exists(meta_path):
        try:
            with open(meta_path, "r", encoding="utf-8") as fh:
                return json.load(fh)
        except (ValueError, OSError):
            return {}
    return {}


def _write_json_atomic(path: str, payload: dict) -> None:
    directory = os.path.dirname(path) or "."
    fd, tmp = tempfile.mkstemp(dir=directory, suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, sort_keys=True)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)


def sync_source(
    *,
    name: str,
    url: str,
    data_dir: str,
    fetcher: Fetcher,
    timestamp: str,
    min_records: int = DEFAULT_MIN_RECORDS,
) -> SyncOutcome:
    """Sync a single source into ``data_dir``.

    ``timestamp`` is supplied by the caller (keeps this function deterministic and
    avoids wall-clock calls inside the unit under test).
    """
    os.makedirs(data_dir, exist_ok=True)
    archive_dir = os.path.join(data_dir, "archive")
    os.makedirs(archive_dir, exist_ok=True)

    live_path = os.path.join(data_dir, f"{name}.xml")
    meta_path = os.path.join(data_dir, f"{name}.meta.json")
    manifest_path = os.path.join(data_dir, f"{name}.manifest.json")

    cache = _read_cache_meta(meta_path)
    try:
        fetched = fetcher(url, cache.get("etag"), cache.get("last_modified"))
    except Exception as exc:  # network / transport failure
        return SyncOutcome(source=name, result="error", detail=str(exc))

    if fetched.status == 304:
        return SyncOutcome(
            source=name,
            result="not-modified",
            record_count=int(cache.get("record_count", 0)),
            sha256=cache.get("sha256"),
            detail="server returned 304 Not Modified",
        )

    if fetched.status != 200 or fetched.content is None:
        return SyncOutcome(
            source=name, result="error", detail=f"unexpected status {fetched.status}"
        )

    content = fetched.content
    digest = _sha256(content)

    if digest == cache.get("sha256"):
        return SyncOutcome(
            source=name,
            result="unchanged",
            record_count=int(cache.get("record_count", 0)),
            sha256=digest,
            detail="fingerprint identical to live data",
        )

    # Validate BEFORE promoting: must parse and meet the minimum record count.
    try:
        parties = parse_advanced(content)
    except Exception as exc:
        return SyncOutcome(
            source=name, result="rejected", sha256=digest, detail=f"parse failed: {exc}"
        )

    if len(parties) < min_records:
        return SyncOutcome(
            source=name,
            result="rejected",
            record_count=len(parties),
            sha256=digest,
            detail=f"only {len(parties)} records (< min {min_records}); not promoting",
        )

    # Write temp then atomically promote.
    fd, tmp = tempfile.mkstemp(dir=data_dir, suffix=".xml.tmp")
    with os.fdopen(fd, "wb") as fh:
        fh.write(content)
    os.replace(tmp, live_path)

    # Timestamped archive copy.
    archive_path = os.path.join(archive_dir, f"{name}.{timestamp}.xml")
    with open(archive_path, "wb") as fh:
        fh.write(content)

    manifest = {
        "source": name,
        "url": url,
        "fetched_at": timestamp,
        "sha256": digest,
        "etag": fetched.etag,
        "last_modified": fetched.last_modified,
        "record_count": len(parties),
        "live_path": live_path,
        "archive_path": archive_path,
    }
    _write_json_atomic(manifest_path, manifest)
    _write_json_atomic(
        meta_path,
        {
            "sha256": digest,
            "etag": fetched.etag,
            "last_modified": fetched.last_modified,
            "record_count": len(parties),
            "data_version": timestamp,
        },
    )

    return SyncOutcome(
        source=name,
        result="promoted",
        record_count=len(parties),
        sha256=digest,
        detail=f"promoted {len(parties)} records",
    )


def httpx_fetcher(url: str, etag: str | None, last_modified: str | None) -> FetchResult:
    """Default network fetcher using httpx with conditional headers."""
    import httpx  # imported lazily so tests need no network stack

    headers: dict[str, str] = {}
    if etag:
        headers["If-None-Match"] = etag
    if last_modified:
        headers["If-Modified-Since"] = last_modified
    resp = httpx.get(url, headers=headers, timeout=120.0, follow_redirects=True)
    if resp.status_code == 304:
        return FetchResult(status=304)
    return FetchResult(
        status=resp.status_code,
        content=resp.content if resp.status_code == 200 else None,
        etag=resp.headers.get("ETag"),
        last_modified=resp.headers.get("Last-Modified"),
    )


def sync_all(
    *,
    data_dir: str,
    timestamp: str,
    fetcher: Fetcher = httpx_fetcher,
    min_records: int = DEFAULT_MIN_RECORDS,
) -> list[dict]:
    """Sync both advanced sources; returns a list of outcome dicts."""
    outcomes = []
    for name, url in (("sdn_advanced", SDN_ADVANCED_URL), ("cons_advanced", CONS_ADVANCED_URL)):
        outcome = sync_source(
            name=name,
            url=url,
            data_dir=data_dir,
            fetcher=fetcher,
            timestamp=timestamp,
            min_records=min_records,
        )
        outcomes.append(asdict(outcome))
    return outcomes
