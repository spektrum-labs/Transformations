"""
Transformation: isRiskPrioritizationTrue
Vendor: Tenable  |  Category: Attack Surface Management  |  Method: getRecentlyChangedAssets (POST /inventory with bd.severity_ranking)
Evaluates: bd.severity_ranking is populated on the sampled assets: ASM's risk ranking is active
API: Tenable ASM v1.0 (https://developer.tenable.com/reference/globalsearch), asm.cloud.tenable.com/api/1.0
"""

import json
from datetime import datetime, timedelta, timezone

VENDOR = "Tenable"
CATEGORY = "Attack Surface Management"


def _parse(input):
    if isinstance(input, str):
        return json.loads(input)
    if isinstance(input, bytes):
        return json.loads(input.decode("utf-8"))
    return input


def extract_input(input_data):
    """The engine hands `{"data": <api response>, "validation": {...}}`; older callers hand the
    bare response, sometimes under a wrapper key. Returns (response, validation)."""
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        for _ in range(3):
            moved = False
            for key in ("api_response", "response", "result", "apiResponse", "Output"):
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
    """`POST /inventory` -> {"total", "hiddenCount", "stats", "assets": [...]}. A bare list is
    tolerated (some proxies unwrap). Never invents a total: when the API omitted it (paging
    with `after`), the count of returned assets is what we know."""
    if isinstance(data, list):
        return data, len(data), {}
    if not isinstance(data, dict):
        return [], None, {}
    assets = data.get("assets") or []
    total = data.get("total")
    if total is None:
        total = len(assets)
    return assets, int(total), data.get("stats") or {}


def _items(data, *keys):
    """A list endpoint (`/sources`, `/smartfolders`) -> its items, whether bare or wrapped."""
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
            # epoch ms (bd.addedtoportfolio) or s
            v = float(value)
            return datetime.fromtimestamp(v / 1000 if v > 1e11 else v, tz=timezone.utc)
        s = str(value).replace("Z", "+00:00")
        d = datetime.fromisoformat(s)
        return d if d.tzinfo else d.replace(tzinfo=timezone.utc)
    except Exception:
        return None


def _run(input, criteria_key, evaluate, transformation_id):
    """Shared driver: parse, unwrap, evaluate, and wrap in the v1.0 response contract. `evaluate`
    returns (value, extras, pass_reasons, fail_reasons, recommendations, api_errors)."""
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

RANKS = {"critical", "high", "medium", "low", "none"}


def evaluate(data):
    assets, total, _ = _assets(data)
    ranked = [a for a in assets if isinstance(a, dict) and str(a.get("bd.severity_ranking") or "").lower() in RANKS]
    dist = {}
    for a in ranked:
        r = str(a.get("bd.severity_ranking")).lower()
        dist[r] = dist.get(r, 0) + 1
    extras = {"sampledAssets": len(assets), "rankedAssets": len(ranked), "severityDistribution": dist}
    if not assets:
        return False, extras, [], ["no assets in the sample"], ["Confirm the inventory holds assets"], []
    if len(ranked) == len(assets):
        return True, extras, [f"all {len(assets)} sampled assets carry a severity ranking"], [], [], []
    return False, extras, [], [f"{len(assets) - len(ranked)} of {len(assets)} sampled assets carry no severity ranking"], ["Risk ranking is not applied to every asset; review inventory enrichment"], []


def transform(input):
    return _run(input, "isRiskPrioritizationTrue", evaluate, "isRiskPrioritizationTrue")
