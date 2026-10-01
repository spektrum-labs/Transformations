"""Transformation: hasNetworkTunnelsConfigured - Cisco Secure Access, method getNetworkTunnelGroups.

Reads a complete GET https://api.sse.cisco.com/deployments/v2/networktunnelgroups list
({"data": [...], "offset", "limit", "total"}). Each network tunnel group carries a group-level
status of "connected", "warning" or "disconnected". The answer is True when at least one group is
connected or warning (traffic reaches Secure Access), False when the complete list has no such
group (including a genuine empty list with total 0), and None when the body is missing, an error,
unrelated, or partial (fewer groups than total). Counts and the connected percentage are returned
alongside.
"""
import json
from datetime import datetime

KEY = "hasNetworkTunnelsConfigured"
LIVE = ("connected", "warning")
DOWN = ("disconnected",)


def extract_input(input_data):
    """(raw body, validation). The {data, validation} envelope keeps the undrilled body, so the
    total field stays visible and a partial read is caught."""
    if isinstance(input_data, dict) and "validation" in input_data and isinstance(input_data["validation"], dict):
        return input_data.get("data"), input_data["validation"]
    return input_data, {"status": "unknown", "errors": [], "warnings": ["Legacy input format - no schema validation performed"]}


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, metadata=None,
                    transformation_errors=None, api_errors=None, additional_findings=None):
    """Standardized 5-section transformation response."""
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    api_err_list = api_errors or []
    transform_err_list = transformation_errors or []
    response_metadata = {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "2.0"}
    if metadata:
        response_metadata.update(metadata)
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error" if api_err_list else "success", "errors": api_err_list},
            "validation": {
                "status": validation.get("status", "unknown"),
                "errors": validation.get("errors", []),
                "warnings": validation.get("warnings", []),
            },
            "transformation": {
                "status": "error" if transform_err_list else "success",
                "errors": transform_err_list,
                "inputSummary": input_summary or {},
            },
            "evaluation": {
                "passReasons": pass_reasons or [],
                "failReasons": fail_reasons or [],
                "recommendations": recommendations or [],
                "additionalFindings": additional_findings or [],
            },
            "metadata": response_metadata,
        },
    }


def error_text(obj):
    """A vendor or transport error carried by a dict, or None."""
    if not isinstance(obj, dict):
        return None
    if obj.get("error") is True or obj.get("errors"):
        return json.dumps(obj.get("errors") or obj.get("message") or obj.get("error"))[:300]
    if isinstance(obj.get("error"), str) and obj.get("error"):
        return obj.get("error")[:300]
    code = obj.get("statusCode", obj.get("status_code", obj.get("code")))
    if isinstance(code, int) and not isinstance(code, bool) and code >= 400:
        return "HTTP " + str(code) + ": " + str(obj.get("message") or obj.get("detail") or "")[:200]
    return None


def find_page(obj):
    """(groups, total, problem) from the networktunnelgroups envelope, whatever wrapper arrives."""
    cur = obj
    for depth in range(6):
        if isinstance(cur, str):
            try:
                cur = json.loads(cur)
            except Exception:
                return None, None, "Secure Access returned a non-JSON body; nothing was measured."
        if not isinstance(cur, dict):
            return None, None, "No Secure Access network tunnel group list in the response; nothing was measured."
        problem = error_text(cur)
        if problem:
            return None, None, "Secure Access returned an error instead of tunnel groups: " + problem
        total = cur.get("total")
        if isinstance(cur.get("data"), list) and isinstance(total, int) and not isinstance(total, bool) and total >= 0:
            return cur["data"], total, None
        nxt = None
        for key in ["data", "result", "response", "apiResponse", "api_response", "Output"]:
            if isinstance(cur.get(key), (dict, str)):
                nxt = cur.get(key)
                break
        if nxt is None:
            return None, None, ("The response carries no network tunnel group list with an integer total, "
                                "so a complete read cannot be shown.")
        cur = nxt
    return None, None, "No Secure Access network tunnel group list in the response; nothing was measured."


def not_measured(problem, validation):
    return create_response(
        result={KEY: None},
        validation=validation,
        fail_reasons=[problem],
        api_errors=[problem],
        metadata={"transformationId": KEY, "vendor": "Cisco Secure Access", "category": "networksecurity"},
    )


def transform(input):
    raw, validation = extract_input(input)
    try:
        groups, total, problem = find_page(raw)
        if problem is not None:
            return not_measured(problem, validation)
        groups = [g for g in groups if isinstance(g, dict)]
        if len(groups) < total:
            return not_measured("Read " + str(len(groups)) + " of " + str(total)
                                + " network tunnel groups; a partial read is not scored.", validation)
        no_status = [g for g in groups if not str(g.get("status") or "").strip()]
        if no_status:
            return not_measured(str(len(no_status)) + " of " + str(len(groups))
                                + " network tunnel groups carry no status; the list cannot be judged.", validation)
        live = [g for g in groups if str(g.get("status")).strip().lower() in LIVE]
        connected = [g for g in live if str(g.get("status")).strip().lower() == "connected"]
        down = [g for g in groups if str(g.get("status")).strip().lower() in DOWN]
        count = len(groups)
        pct = round(100.0 * len(connected) / count, 2) if count else 0.0
        configured = len(live) > 0
        result = {
            KEY: configured,
            "totalTunnelGroups": count,
            "connectedTunnelGroups": len(connected),
            "warningTunnelGroups": len(live) - len(connected),
            "disconnectedTunnelGroups": len(down),
            "connectedTunnelGroupPercentage": pct,
        }
        pass_reasons, fail_reasons, recommendations = [], [], []
        if configured:
            names = [str(g.get("name") or g.get("id")) for g in live[:5]]
            pass_reasons.append(str(len(live)) + " of " + str(count) + " Secure Access network tunnel group(s) "
                                + "are connected or degraded (" + str(len(connected)) + " fully connected, "
                                + str(pct) + "%): " + ", ".join(names))
        elif count == 0:
            fail_reasons.append("Secure Access reports no network tunnel groups, so no site traffic is "
                                "tunnelled to Secure Access.")
            recommendations.append("Create a network tunnel group under Connect > Network Connections and "
                                   "bring up its IPsec tunnels.")
        else:
            fail_reasons.append("All " + str(count) + " Secure Access network tunnel group(s) are disconnected.")
            recommendations.append("Investigate why the network tunnel groups' IPsec tunnels are down.")
        return create_response(
            result=result,
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={"totalTunnelGroups": count, "liveTunnelGroups": len(live)},
            metadata={"transformationId": KEY, "vendor": "Cisco Secure Access", "category": "networksecurity"},
        )
    except Exception as e:
        problem = "Transformation error: " + str(e)
        return create_response(
            result={KEY: None},
            validation=validation,
            transformation_errors=[str(e)],
            fail_reasons=[problem],
            api_errors=[problem],
            metadata={"transformationId": KEY, "vendor": "Cisco Secure Access", "category": "networksecurity"},
        )
