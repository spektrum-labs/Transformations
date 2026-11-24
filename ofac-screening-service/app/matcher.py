"""Fuzzy name matching over parsed OFAC parties.

Matching normalizes both the query and every candidate (primary + alias) name and
scores them with RapidFuzz ``token_set_ratio`` — which is order-insensitive and
tolerant of extra/missing tokens, so reversed name order and partial names still
score highly.

A score at/above ``match_threshold`` is a **potential match** surfaced for human
adjudication. A ``potential_match`` is *never* an auto-confirmed hit.
"""

from __future__ import annotations

import os
import unicodedata
from dataclasses import dataclass

from rapidfuzz import fuzz

from .parser import Party, dedupe_parties, parse_advanced

# Default screening thresholds (0-100). ``clear`` below this and no potential
# matches => the name clears.
DEFAULT_MATCH_THRESHOLD = 85.0


def normalize_name(name: str) -> str:
    """Lower-case, strip accents/punctuation, and collapse whitespace."""
    if not name:
        return ""
    # Decompose accents and drop combining marks (José -> jose).
    decomposed = unicodedata.normalize("NFKD", name)
    stripped = "".join(c for c in decomposed if not unicodedata.combining(c))
    out_chars = [c.lower() if c.isalnum() else " " for c in stripped]
    return " ".join("".join(out_chars).split())


@dataclass
class NameHit:
    matched_name: str
    is_primary: bool
    score: float


@dataclass
class PartyMatch:
    fixed_ref: str
    entity_type: str
    primary_name: str
    score: float
    matched_name: str
    matched_on_primary: bool


def _best_name_hit(query_norm: str, party: Party) -> NameHit | None:
    best: NameHit | None = None
    names = party.all_names
    primary_norm = normalize_name(party.primary_name)
    for name in names:
        cand_norm = normalize_name(name)
        if not cand_norm:
            continue
        score = fuzz.token_set_ratio(query_norm, cand_norm)
        if best is None or score > best.score:
            best = NameHit(
                matched_name=name,
                is_primary=(cand_norm == primary_norm),
                score=float(score),
            )
    return best


def screen_name(
    query: str,
    parties: list[Party],
    *,
    entity_type: str | None = None,
    match_threshold: float = DEFAULT_MATCH_THRESHOLD,
) -> list[PartyMatch]:
    """Return potential matches for ``query`` sorted best-first.

    ``entity_type`` (case-insensitive) restricts candidates to that party type.
    """
    query_norm = normalize_name(query)
    if not query_norm:
        return []

    wanted_type = entity_type.strip().lower() if entity_type else None
    matches: list[PartyMatch] = []
    for party in parties:
        if wanted_type and party.entity_type.lower() != wanted_type:
            continue
        hit = _best_name_hit(query_norm, party)
        if hit is None or hit.score < match_threshold:
            continue
        matches.append(
            PartyMatch(
                fixed_ref=party.fixed_ref,
                entity_type=party.entity_type,
                primary_name=party.primary_name,
                score=hit.score,
                matched_name=hit.matched_name,
                matched_on_primary=hit.is_primary,
            )
        )
    matches.sort(key=lambda m: m.score, reverse=True)
    return matches


class PartyStore:
    """Holds parsed parties and hot-reloads when the backing file's mtime changes.

    No process restart is required when the hourly sync promotes a new data file.
    """

    def __init__(self, data_path: str, data_version: str = "unknown") -> None:
        self.data_path = data_path
        self.data_version = data_version
        self._parties: list[Party] = []
        self._mtime: float | None = None

    @property
    def parties(self) -> list[Party]:
        self._maybe_reload()
        return self._parties

    def load_from_bytes(self, xml_bytes: bytes, data_version: str = "unknown") -> None:
        """Load directly from bytes (used in tests and initial in-memory seeding)."""
        self._parties = parse_advanced(xml_bytes)
        self.data_version = data_version

    def _maybe_reload(self) -> None:
        if not self.data_path or not os.path.exists(self.data_path):
            return
        mtime = os.path.getmtime(self.data_path)
        if self._mtime is not None and mtime == self._mtime:
            return
        with open(self.data_path, "rb") as fh:
            xml_bytes = fh.read()
        parsed = parse_advanced(xml_bytes)
        # Support a directory of multiple advanced files sharing one store is out
        # of scope here; a single promoted file is the contract.
        self._parties = dedupe_parties(parsed)
        self._mtime = mtime
