"""
Transformation: offlineSensorCount
Vendor: Halcyon  |  Category: Endpoint Security

Integration-Service method checkInstalled (the EPP base method for a tenant's installation status): GET https://api.halcyon.ai/search/devices/metrics (header X-TenantID).
Source: the vendor's public OpenAPI, api.halcyon.ai/docs, operation "GET /search/devices/metrics", whose
response DeviceMetrics holds three required int32 fields: total, no_heartbeats and need_updates.
Value: the vendor's own `no_heartbeats` count, the devices the vendor reports as having no heartbeat (offline).

Population: every device registered to the tenant named in X-TenantID (total). The vendor does not publish how
long without a heartbeat counts as "no heartbeat" or what "needs update" is measured against, so the figure is the
vendor's as given: this transform adds no time window and cannot split long-stale devices out of it.
Fail closed (Not evaluated, never a pass, never 0): an error or refused (401/403) answer, an empty, unrecognised
or non-JSON body, a body that lacks any of the three fields or holds one that is not a whole number of zero or
more, a count larger than total, and a tenant with no registered devices all give null.
"""

import json
from datetime import datetime, timezone

VENDOR = "Halcyon"
CATEGORY = "Endpoint Security"
KEY = "offlineSensorCount"
FIELD = "no_heartbeats"
FIELDS = ("total", "no_heartbeats", "need_updates")
# Integration-Service wraps a method response in one of these; Halcyon's own body is the bare object.
WRAPPERS = ("api_response", "response", "result", "apiResponse", "Output", "data")


def parse(value):
    if isinstance(value, bytes):
        value = value.decode("utf-8")
    if isinstance(value, str):
        if not value.strip():
            return None
        return json.loads(value)
    return value


def is_count(value):
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def error_text(node):
    """Why a dict is an error answer rather than the vendor's metrics, or None."""
    code = node.get("statusCode")
    status = node.get("status")
    if node.get("error") is True or node.get("errorType"):
        return "error answer (" + str(node.get("statusCode") or node.get("errorType")) + "): " + str(
            node.get("message") or node.get("error") or "")[:160]
    for number in (code, status):
        if isinstance(number, int) and not isinstance(number, bool) and number >= 400:
            return "HTTP " + str(number) + ": " + str(node.get("message") or "")[:160]
    if status is False:
        return "the vendor answered status false: " + str(node.get("message") or "")[:160]
    return None


def find_metrics(data):
    """(metrics, problem): the DeviceMetrics object found under any wrapper, or why there is none."""
    node = data
    for depth in range(6):
        if not isinstance(node, dict):
            return None, "the response is empty or not a JSON object"
        problem = error_text(node)
        if problem:
            return None, problem
        for name in FIELDS:
            if name in node:
                return node, None
        nxt = None
        for key in WRAPPERS:
            inner = node.get(key)
            if isinstance(inner, (str, bytes)):
                inner = parse(inner)
            if isinstance(inner, dict):
                nxt = inner
                break
        if nxt is None:
            break
        node = nxt
    if isinstance(node, dict) and (node.get("message") or node.get("detail")):
        return None, "vendor message: " + str(node.get("message") or node.get("detail"))[:160]
    return None, "no device metrics in the response"


def device_metrics(input):
    """(metrics, problem): the three counts of a coherent answer, or why nothing was measured."""
    node, problem = find_metrics(parse(input))
    if problem:
        return None, problem
    for name in FIELDS:
        if not is_count(node.get(name)):
            return None, "the response has no whole-number " + name + " (zero or more), so it was not measured"
    if node["total"] == 0:
        return None, "the tenant has no registered devices, so nothing was measured"
    if node["no_heartbeats"] > node["total"] or node["need_updates"] > node["total"]:
        return None, "a count is larger than the total of registered devices, so the answer is not coherent"
    return node, None


def build_response(result, pass_reasons=None, fail_reasons=None, errors=None, summary=None,
                   recommendations=None, transform_id=""):
    errors = errors or []
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error" if errors else "success", "errors": errors},
            "validation": {"status": "unknown", "errors": [], "warnings": []},
            "transformation": {"status": "error" if errors else "success", "errors": errors,
                               "inputSummary": summary or {}},
            "evaluation": {"passReasons": pass_reasons or [], "failReasons": fail_reasons or [],
                           "recommendations": recommendations or [], "additionalFindings": []},
            "metadata": {"evaluatedAt": datetime.now(timezone.utc).isoformat(), "schemaVersion": "1.0",
                         "transformationId": transform_id, "vendor": VENDOR, "category": CATEGORY},
        },
    }


def transform(input):
    try:
        metrics, problem = device_metrics(input)
        if problem:
            return build_response({KEY: None}, errors=[problem], transform_id=KEY)
        count = metrics[FIELD]
        total = metrics["total"]
        summary = {"registeredDevices": total, KEY: count, "noHeartbeats": metrics["no_heartbeats"],
                   "needUpdates": metrics["need_updates"], "windowApplied": "none, the vendor's own count"}
        if count > 0:
            return build_response({KEY: count}, fail_reasons=[
                str(count) + " of " + str(total) + " registered devices have no heartbeat, by the vendor's own count"], summary=summary,
                recommendations=["Check the Halcyon agent on the devices that stopped sending heartbeats: confirm each device is on and online, or retire it from the Halcyon console if it is gone."], transform_id=KEY)
        return build_response({KEY: 0}, pass_reasons=[
            "None of the " + str(total) + " registered devices has no heartbeat, by the vendor's own count"], summary=summary, transform_id=KEY)
    except Exception as error:
        return build_response({KEY: None}, errors=[str(error)[:300]], transform_id=KEY)
