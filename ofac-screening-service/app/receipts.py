"""L4 evidence receipts for each screening decision.

Every screen emits a canonical JSON receipt whose ``content_hash`` is the sha256
of the *deterministic claim* — the stable, decision-bearing fields only. The hash
deliberately **excludes** ``receipt_id`` and ``created_at`` so that two screens of
the same name against the same data version produce the same ``content_hash`` (it
is the value that feeds the Merkle tree). A matching ``evidence_item`` is emitted
ready to attach to the unified-attestation-token at proof level 4.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Any


def _canonical_claim(
    *,
    query_name: str,
    entity_type: str | None,
    status: str,
    match_threshold: float,
    data_version: str,
    potential_matches: list[dict[str, Any]],
) -> dict[str, Any]:
    """The deterministic, decision-bearing subset that gets hashed.

    Potential-match entries are reduced to their stable identifiers and sorted so
    ordering never perturbs the hash.
    """
    reduced_matches = sorted(
        (
            {
                "fixed_ref": m.get("fixed_ref", ""),
                "matched_name": m.get("matched_name", ""),
                "score": round(float(m.get("score", 0.0)), 2),
            }
            for m in potential_matches
        ),
        key=lambda m: (m["fixed_ref"], m["matched_name"], m["score"]),
    )
    return {
        "claim_type": "ofac_screening",
        "query_name": query_name,
        "entity_type": entity_type or "any",
        "status": status,
        "match_threshold": round(float(match_threshold), 2),
        "data_version": data_version,
        "potential_matches": reduced_matches,
    }


def compute_content_hash(claim: dict[str, Any]) -> str:
    """sha256 over the canonical JSON serialization of the claim."""
    serialized = json.dumps(claim, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def build_receipt(
    *,
    query_name: str,
    entity_type: str | None,
    status: str,
    match_threshold: float,
    data_version: str,
    potential_matches: list[dict[str, Any]],
    created_at: str | None = None,
    receipt_id: str | None = None,
) -> dict[str, Any]:
    """Build the canonical JSON receipt including its ``content_hash``.

    ``created_at``/``receipt_id`` may be injected for deterministic tests; they do
    not affect ``content_hash``.
    """
    claim = _canonical_claim(
        query_name=query_name,
        entity_type=entity_type,
        status=status,
        match_threshold=match_threshold,
        data_version=data_version,
        potential_matches=potential_matches,
    )
    content_hash = compute_content_hash(claim)
    return {
        "receipt_id": receipt_id or str(uuid.uuid4()),
        "created_at": created_at or datetime.now(timezone.utc).isoformat(),
        "claim": claim,
        "content_hash": content_hash,
        "potential_matches": potential_matches,
    }


def receipt_to_html(receipt: dict[str, Any]) -> str:
    """Render a minimal, self-contained HTML view of a receipt."""
    claim = receipt["claim"]
    rows = "".join(
        f"<tr><td>{m.get('matched_name', '')}</td>"
        f"<td>{m.get('fixed_ref', '')}</td>"
        f"<td>{m.get('score', '')}</td></tr>"
        for m in receipt.get("potential_matches", [])
    )
    matches_table = (
        f"<table><thead><tr><th>Matched name</th><th>FixedRef</th><th>Score</th></tr>"
        f"</thead><tbody>{rows}</tbody></table>"
        if rows
        else "<p>No potential matches.</p>"
    )
    return (
        "<!doctype html><html><head><meta charset='utf-8'>"
        "<title>OFAC Screening Receipt</title></head><body>"
        "<h1>OFAC Screening Receipt</h1>"
        f"<p><strong>Query:</strong> {claim['query_name']}</p>"
        f"<p><strong>Entity type:</strong> {claim['entity_type']}</p>"
        f"<p><strong>Status:</strong> {claim['status']}</p>"
        f"<p><strong>Data version:</strong> {claim['data_version']}</p>"
        f"<p><strong>Receipt ID:</strong> {receipt['receipt_id']}</p>"
        f"<p><strong>Created at:</strong> {receipt['created_at']}</p>"
        f"<p><strong>Content hash (sha256):</strong> <code>{receipt['content_hash']}</code></p>"
        f"<h2>Potential matches</h2>{matches_table}"
        "</body></html>"
    )


def build_evidence_item(receipt: dict[str, Any]) -> dict[str, Any]:
    """A ready-to-attach L4 evidence item for the unified-attestation-token."""
    claim = receipt["claim"]
    return {
        "type": "ofac_screening",
        "source": "automated",
        "proofLevel": "4",
        "contentHash": receipt["content_hash"],
        "receiptId": receipt["receipt_id"],
        "createdAt": receipt["created_at"],
        "summary": {
            "queryName": claim["query_name"],
            "entityType": claim["entity_type"],
            "status": claim["status"],
            "dataVersion": claim["data_version"],
            "potentialMatchCount": len(receipt.get("potential_matches", [])),
        },
    }
