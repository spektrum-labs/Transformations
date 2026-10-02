"""
Transformation: exposedAdminPortsCount
Vendor: Tenable  |  Category: Attack Surface Management  |  Method: getInventory (POST /inventory, paged)
Evaluates: internet-facing assets exposing remote-admin or database ports
Reads: ports.ports
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


def inventory_problem(data):
    """Why this body proves nothing about the estate, else None. POST /inventory always answers with an
    `assets` list; an empty, missing or error reply (no list, or a list with no asset) is not a clean estate."""
    if isinstance(data, list):
        assets = data
    elif isinstance(data, dict) and isinstance(data.get("assets"), list):
        assets = data.get("assets")
    else:
        return "the inventory response carries no asset list (empty, missing or error reply), so the count is unknown, not 0"
    if not [a for a in assets if isinstance(a, dict)]:
        return "the inventory returned no assets, so the count is unknown, not 0"
    return None


def unevaluated(criteria_key, reason, validation, transformation_id, extras=None):
    """Fail closed: None with the reason in dataCollection.errors, which Token-Service reads as Unevaluated."""
    result = dict(extras or {})
    result[criteria_key] = None
    return create_response(result, validation, fail_reasons=[reason], api_errors=[reason],
                           recommendations=["Confirm the ASM API key can read the inventory"],
                           input_summary=result, transformation_id=transformation_id)


def run_criterion(input, criteria_key, evaluate, transformation_id):
    try:
        data, validation = extract_input(parse_payload(input))
        if validation.get("status") == "failed":
            return unevaluated(criteria_key, "Input validation failed: the inventory response did not match its schema, so the count is unknown",
                               validation, transformation_id)
        problem = inventory_problem(data)
        if problem:
            return unevaluated(criteria_key, problem, validation, transformation_id)
        value, extras, passes, fails, recs, api_errors = evaluate(data)
        if value == 0 and not isinstance(value, bool) and extras.get("partial") is True:
            reason = (f"scanned {extras.get('assetsScanned')} of {extras.get('inventoryTotal')} assets; "
                      "zero on a partial inventory is not a clean estate, so the count is unknown")
            return unevaluated(criteria_key, reason, validation, transformation_id, extras)
        return create_response({criteria_key: value, **extras}, validation, pass_reasons=passes, fail_reasons=fails,
                               recommendations=recs, input_summary={criteria_key: value, **extras},
                               api_errors=api_errors, transformation_id=transformation_id)
    except Exception as e:  # noqa: BLE001 - a transformation never raises into the engine
        return unevaluated(criteria_key, f"Transformation error, so the count is unknown: {e}",
                           {"status": "error", "errors": [], "warnings": []}, transformation_id)

def matches(a):
    return any(int(p) in ADMIN_PORTS for p in as_list(a, "ports.ports") if str(p).isdigit())


def evaluate(data):
    assets, total, stats_unused, partial = read_assets(data)
    if not isinstance(assets, list):
        return None, {"count": None}, [], ["inventory response unreadable"], ["Confirm the API key can read the inventory"], ["unreadable inventory response"]
    n, sample = count_matching(assets, matches, 'bd.original_hostname')
    extras = {"count": n, "assetsScanned": len(assets), "inventoryTotal": total, "sample": sample}
    if partial:
        extras["partial"] = True
        extras["note"] = f"scanned {len(assets)} of {total} assets; this count is a lower bound"
    if n == 0:
        return 0, extras, [f"no asset(s) exposing a remote-admin or database port to the internet across {len(assets)} scanned asset(s)"], [], [], []
    return n, extras, [], [f"{n} asset(s) exposing a remote-admin or database port to the internet"], ['Close or firewall these ports; put administrative access behind a VPN or bastion'], []


def transform(input):
    return run_criterion(input, "exposedAdminPortsCount", evaluate, "exposedAdminPortsCount")
