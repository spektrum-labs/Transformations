"""Parsers for OFAC list exports.

OFAC ships two XML shapes:

* **Advanced** (``SDN_ADVANCED.XML`` / ``CONS_ADVANCED.XML``) — the modern,
  namespaced schema built around ``<DistinctParty>`` / ``<SanctionsEntry>``.
  Names live several levels deep under
  ``DistinctParty/Profile/Identity/Alias/DocumentedName/DocumentedNamePart/NamePartValue``
  and the entity type is an id on ``Profile/@PartySubTypeID`` resolved through
  ``ReferenceValueSets/PartySubTypeValues``.
* **Legacy** (``SDN.XML``) — the old flat ``<sdnEntry>`` schema with
  ``<firstName>``/``<lastName>``/``<sdnType>``.

The legacy ``sdnEntry`` path finds **zero** records in an advanced export (the
element simply does not exist there). Screening must therefore use
:func:`parse_advanced`; :func:`parse_legacy_sdn` is retained only so the
regression is explicit and testable.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Iterable


@dataclass
class Party:
    """A sanctioned party normalized out of either schema."""

    fixed_ref: str
    entity_type: str  # "Individual" | "Entity" | "Vessel" | "Aircraft" | "Unknown"
    primary_name: str
    aliases: list[str] = field(default_factory=list)

    @property
    def all_names(self) -> list[str]:
        names = [self.primary_name] + list(self.aliases)
        # de-dup while preserving order, drop empties
        seen: set[str] = set()
        out: list[str] = []
        for n in names:
            key = n.strip().lower()
            if n.strip() and key not in seen:
                seen.add(key)
                out.append(n.strip())
        return out


def _local(tag: str) -> str:
    """Return the local-name of a possibly namespaced tag (``{ns}Name`` -> ``Name``)."""
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag


def _findall_local(elem: ET.Element, name: str) -> list[ET.Element]:
    return [c for c in elem.iter() if _local(c.tag) == name]


def _children_local(elem: ET.Element, name: str) -> list[ET.Element]:
    return [c for c in list(elem) if _local(c.tag) == name]


def _first_local(elem: ET.Element, name: str) -> ET.Element | None:
    for c in elem.iter():
        if _local(c.tag) == name:
            return c
    return None


def _party_subtype_map(root: ET.Element) -> dict[str, str]:
    """Map ``PartySubType`` id -> human label (Individual/Entity/Vessel/Aircraft)."""
    mapping: dict[str, str] = {}
    for pst in _findall_local(root, "PartySubType"):
        pid = pst.get("ID") or pst.get("Id") or pst.get("id")
        label = (pst.text or "").strip()
        if pid and label:
            mapping[pid] = label
    return mapping


def _documented_name_text(documented_name: ET.Element) -> str:
    """Join the ``NamePartValue`` fragments of a ``DocumentedName`` in doc order."""
    parts: list[str] = []
    for npv in _findall_local(documented_name, "NamePartValue"):
        val = (npv.text or "").strip()
        if val:
            parts.append(val)
    return " ".join(parts).strip()


def parse_advanced(xml_bytes: bytes) -> list[Party]:
    """Parse a namespaced OFAC *advanced* export into :class:`Party` records."""
    root = ET.fromstring(xml_bytes)
    subtype_map = _party_subtype_map(root)

    parties: list[Party] = []
    for dp in _findall_local(root, "DistinctParty"):
        fixed_ref = dp.get("FixedRef") or dp.get("fixedRef") or ""
        profile = _first_local(dp, "Profile")
        if profile is None:
            continue

        subtype_id = profile.get("PartySubTypeID") or profile.get("partySubTypeId")
        entity_type = subtype_map.get(subtype_id or "", "Unknown")

        primary_name = ""
        aliases: list[str] = []
        for alias in _findall_local(profile, "Alias"):
            is_primary = (alias.get("IsPrimary") or "").lower() == "true"
            for documented_name in _children_local(alias, "DocumentedName"):
                name = _documented_name_text(documented_name)
                if not name:
                    continue
                if is_primary and not primary_name:
                    primary_name = name
                else:
                    aliases.append(name)

        # Fall back to the first alias if none was flagged primary.
        if not primary_name and aliases:
            primary_name = aliases.pop(0)

        if primary_name or aliases:
            parties.append(
                Party(
                    fixed_ref=fixed_ref,
                    entity_type=entity_type,
                    primary_name=primary_name,
                    aliases=aliases,
                )
            )
    return parties


def parse_legacy_sdn(xml_bytes: bytes) -> list[Party]:
    """Parse the legacy flat ``<sdnEntry>`` schema.

    Returns ``[]`` for an advanced export because ``sdnEntry`` is absent there —
    this is the exact failure mode the advanced parser fixes.
    """
    root = ET.fromstring(xml_bytes)
    parties: list[Party] = []
    for entry in _findall_local(root, "sdnEntry"):
        uid = ""
        first = last = ""
        sdn_type = "Unknown"
        aliases: list[str] = []
        for child in list(entry):
            tag = _local(child.tag)
            text = (child.text or "").strip()
            if tag == "uid":
                uid = text
            elif tag == "firstName":
                first = text
            elif tag == "lastName":
                last = text
            elif tag == "sdnType":
                sdn_type = text or "Unknown"
            elif tag == "akaList":
                for aka in _findall_local(child, "aka"):
                    a_first = a_last = ""
                    for ac in list(aka):
                        if _local(ac.tag) == "firstName":
                            a_first = (ac.text or "").strip()
                        elif _local(ac.tag) == "lastName":
                            a_last = (ac.text or "").strip()
                    aka_name = " ".join(p for p in [a_first, a_last] if p).strip()
                    if aka_name:
                        aliases.append(aka_name)
        primary = " ".join(p for p in [first, last] if p).strip()
        if primary or aliases:
            parties.append(
                Party(
                    fixed_ref=uid,
                    entity_type=sdn_type,
                    primary_name=primary or (aliases.pop(0) if aliases else ""),
                    aliases=aliases,
                )
            )
    return parties


def dedupe_parties(*groups: Iterable[Party]) -> list[Party]:
    """Merge parties from several lists, de-duplicating on ``fixed_ref``."""
    by_ref: dict[str, Party] = {}
    order: list[str] = []
    for group in groups:
        for party in group:
            key = party.fixed_ref or party.primary_name.lower()
            if key not in by_ref:
                by_ref[key] = party
                order.append(key)
    return [by_ref[k] for k in order]
