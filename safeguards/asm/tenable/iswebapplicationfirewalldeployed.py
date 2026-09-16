"""
Transformation: isWebApplicationFirewallDeployed
Vendor: Tenable  |  Category: Attack Surface Management  |  Method: getInventory (POST /inventory, paged)
Evaluates: a WAF or CDN is detected in front of the web estate
Reads: wtech.Web Application Firewall
API: Tenable ASM v1.0 -- asm.cloud.tenable.com/api/1.0
     (developer.tenable.com/reference/globalsearch, .../docs/asm-filtering)
"""

import json
from datetime import datetime, timezone

VENDOR = "Tenable"
CATEGORY = "Attack Surface Management"
ADMIN_PORTS = {22, 23, 25, 135, 139, 445, 1433, 1521, 2375, 3306, 3389, 5432, 5900, 5984, 6379, 9200, 11211, 27017}
SECURITY_HEADERS = {"strict-transport-security", "content-security-policy", "x-frame-options", "x-content-type-options"}


def _parse(input):
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


def _assets(data):
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


def _items(data, *keys):
    """A list endpoint (/sources, /smartfolders, /business/azure-keys) -> its items."""
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for k in keys:
            if isinstance(data.get(k), list):
                return data[k]
    return None


def _iso(value):
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


def _listy(asset, key):
    v = asset.get(key)
    if isinstance(v, list):
        return v
    if v in (None, "", False):
        return []
    return [v]


def _count(assets, predicate, sample_key="bd.original_hostname", limit=25):
    """Count matching assets and keep a small, non-sensitive sample of hostnames."""
    hits = [a for a in assets if isinstance(a, dict) and predicate(a)]
    return len(hits), [a.get(sample_key) for a in hits if a.get(sample_key)][:limit]


def _run(input, criteria_key, evaluate, transformation_id):
    try:
        data, validation = extract_input(_parse(input))
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

def evaluate(data):
    assets, total, _stats, partial = _assets(data)
    web = [a for a in assets if isinstance(a, dict) and (_listy(a, "own_header.secnames") or a.get("wtech.has_login") is not None or _listy(a, "ports.ports"))]
    behind = [a for a in assets if isinstance(a, dict) and _listy(a, "wtech.Web Application Firewall")]
    vendors = sorted({str(v) for a in behind for v in _listy(a, "wtech.Web Application Firewall")})
    extras = {"assetsBehindWaf": len(behind), "assetsScanned": len(assets), "wafVendors": vendors, "inventoryTotal": total}
    if partial:
        extras["partial"] = True
    if behind:
        return True, extras, [f"{len(behind)} asset(s) behind a WAF/CDN ({', '.join(vendors[:5]) or 'unnamed'})"], [], [], []
    return False, extras, [], ["no WAF or CDN detected in front of any discovered asset"], ["Front internet-facing web assets with a WAF/CDN"], []


def transform(input):
    return _run(input, "isWebApplicationFirewallDeployed", evaluate, "isWebApplicationFirewallDeployed")
