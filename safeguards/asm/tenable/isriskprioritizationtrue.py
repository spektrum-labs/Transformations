"""
Transformation: isRiskPrioritizationTrue
Vendor: Tenable  |  Category: Attack Surface Management  |  Method: getInventory (POST /inventory, paged)
Evaluates: bd.severity_ranking is populated across the inventory: ASM's risk ranking is active
Reads: bd.severity_ranking
API: Tenable ASM v1.0 -- asm.cloud.tenable.com/api/1.0
     (developer.tenable.com/reference/globalsearch, .../docs/asm-filtering)
"""

import json
from datetime import datetime, timezone

VENDOR = "Tenable"
CATEGORY = "Attack Surface Management"
ADMIN_PORTS = {22, 23, 25, 135, 139, 445, 1433, 1521, 2375, 3306, 3389, 5432, 5900, 5984, 6379, 9200, 11211, 27017}
SECURITY_HEADERS = {"strict-transport-security", "content-security-policy", "x-frame-options", "x-content-type-options"}


def parse_payload(input):
    if isinstance(input, str):
        return json.loads(input)
    if isinstance(input, bytes):
        return json.loads(input.decode("utf-8"))
    return input


def extract_input(input_data):
    """The engine hands {"data": <api response>, "validation": {...}}; older callers hand the
    bare response, sometimes under a wrapper key. Returns (response, validation)."""
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        for _ in range(3):
            moved = False
            for key in ("api_response", "response", "result", "apiResponse", "Output", "_response_data"):
                if key in data and isinstance(data.get(key), (dict, list)):
                    data = data[key]
                    moved = True
                    break
            if not moved:
                break
    return data, {"status": "unknown", "errors": [], "warnings": ["Legacy input format"]}


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, transformation_errors=None,
                    api_errors=None, additional_findings=None, transformation_id=""):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error" if (api_errors or []) else "success", "errors": api_errors or []},
            "validation": {"status": validation.get("status", "unknown"), "errors": validation.get("errors", []), "warnings": validation.get("warnings", [])},
            "transformation": {"status": "error" if (transformation_errors or []) else "success", "errors": transformation_errors or [], "inputSummary": input_summary or {}},
            "evaluation": {"passReasons": pass_reasons or [], "failReasons": fail_reasons or [], "recommendations": recommendations or [], "additionalFindings": additional_findings or []},
            "metadata": {"evaluatedAt": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"), "schemaVersion": "1.0", "transformationId": transformation_id, "vendor": VENDOR, "category": CATEGORY},
        },
    }


def read_assets(data):
    """POST /inventory returns {"total", "stats", "assets": [...]}. Under the engine's cursor
    pagination `assets` holds every page; `total` and `stats` survive from page 1. A bare list is
    tolerated. Returns (assets, total, stats, partial) -- `partial` is True when the pages we hold
    are fewer than the estate, so a count derived from them is a LOWER BOUND and says so."""
    if isinstance(data, list):
        return data, len(data), {}, False
    if not isinstance(data, dict):
        return [], None, {}, False
    assets = data.get("assets") or []
    total = data.get("total")
    stats = data.get("stats") or {}
    partial = isinstance(total, int) and total > len(assets)
    if total is None:
        total = len(assets)
    return assets, int(total), stats, partial


def list_items(data, *keys):
    """A list endpoint (/sources, /smartfolders, /business/azure-keys) -> its items."""
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for k in keys:
            if isinstance(data.get(k), list):
                return data[k]
    return None


def parse_iso_date(value):
    if value in (None, ""):
        return None
    try:
        if isinstance(value, (int, float)):
            v = float(value)
            return datetime.fromtimestamp(v / 1000 if v > 1e11 else v, tz=timezone.utc)
        d = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return d if d.tzinfo else d.replace(tzinfo=timezone.utc)
    except Exception:
        return None


def as_list(asset, key):
    v = asset.get(key)
    if isinstance(v, list):
        return v
    if v in (None, "", False):
        return []
    return [v]


def count_matching(assets, predicate, sample_key="bd.original_hostname", limit=25):
    """Count matching assets and keep a small, non-sensitive sample of hostnames."""
    hits = [a for a in assets if isinstance(a, dict) and predicate(a)]
    return len(hits), [a.get(sample_key) for a in hits if a.get(sample_key)][:limit]


def run_criterion(input, criteria_key, evaluate, transformation_id):
    try:
        data, validation = extract_input(parse_payload(input))
        if validation.get("status") == "failed":
            return create_response({criteria_key: False}, validation, fail_reasons=["Input validation failed"], transformation_id=transformation_id)
        value, extras, passes, fails, recs, api_errors = evaluate(data)
        return create_response({criteria_key: value, **extras}, validation, pass_reasons=passes, fail_reasons=fails,
                               recommendations=recs, input_summary={criteria_key: value, **extras},
                               api_errors=api_errors, transformation_id=transformation_id)
    except Exception as e:  # noqa: BLE001 - a transformation never raises into the engine
        return create_response({criteria_key: False}, {"status": "error", "errors": [], "warnings": []},
                               transformation_errors=[str(e)], fail_reasons=[f"Transformation error: {e}"],
                               transformation_id=transformation_id)

RANKS = {"critical", "high", "medium", "low", "none"}


def evaluate(data):
    assets, total, stats_unused, partial = read_assets(data)
    ranked = [a for a in assets if isinstance(a, dict) and str(a.get("bd.severity_ranking") or "").lower() in RANKS]
    dist = {}
    for a in ranked:
        r = str(a.get("bd.severity_ranking")).lower()
        dist[r] = dist.get(r, 0) + 1
    extras = {"assetsScanned": len(assets), "rankedAssets": len(ranked), "severityDistribution": dist, "inventoryTotal": total}
    if partial:
        extras["partial"] = True
    if not assets:
        return False, extras, [], ["no assets in the inventory"], ["Confirm the inventory holds assets"], []
    if len(ranked) == len(assets):
        return True, extras, [f"all {len(assets)} scanned assets carry a severity ranking"], [], [], []
    return False, extras, [], [f"{len(assets) - len(ranked)} of {len(assets)} scanned assets carry no severity ranking"], ["Risk ranking is not applied to every asset; review inventory enrichment"], []


def transform(input):
    return run_criterion(input, "isRiskPrioritizationTrue", evaluate, "isRiskPrioritizationTrue")
