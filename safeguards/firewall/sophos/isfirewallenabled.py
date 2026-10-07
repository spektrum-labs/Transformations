"""
Transformation: isFirewallEnabled
Vendor: Sophos  |  Category: Firewall

Reads the Firewall Management API list of firewalls, GET https://api-{region}.central.sophos.com/firewall/v1/firewalls
({"items": [firewall], "pages": {...}}). Per firewall, status.connected (boolean, required) says whether the device is
connected to Sophos Central; nothing else in that response says the firewall is running.

The control is "the firewalls are on", so every firewall Central lists must be connected. The earlier version passed
when any one firewall was connected, so 1 of 50 connected with 49 offline was a pass; an offline firewall now fails.
A firewall whose cluster.status is "auxiliary" in an "activePassive" cluster is the standby member of a
high-availability pair and is judged through its primary, so it is reported but not counted; an active-active
auxiliary carries traffic and is counted. The docs do not say whether a standby reports itself connected, so
that exclusion is an interpretation: a standby reporting DISCONNECTED is therefore not evaluated rather than
excluded, which would let an interpretation pass a fleet whose standby is genuinely down.

- True: the list was read whole, it lists at least one firewall, and every counted firewall has status.connected true.
- False: the list was read whole and at least one counted firewall has status.connected false.
- Not evaluated (None, dataCollection error): an error body, a list not read whole (pages.total above pages.current,
  pages.nextKey present, or a full page of pages.size items with no total to say it was the last), no firewall listed,
  or a firewall whose status.connected is absent or neither a boolean nor "true"/"false" (an unrecognised shape is
  not an offline firewall).
"""
import json
from datetime import datetime

CRITERIA_KEY = "isFirewallEnabled"
TRANSFORMATION_ID = "isFirewallEnabled"
CATEGORY = "Firewall"


def extract_input(input_data):
    if isinstance(input_data, (str, bytes)):
        input_data = json.loads(input_data.decode("utf-8") if isinstance(input_data, bytes) else input_data)
    validation = {"status": "unknown", "errors": [], "warnings": ["Legacy input format"]}
    data = input_data
    if isinstance(data, dict) and "data" in data and "validation" in data:
        data, validation = data["data"], data["validation"]
        validation = validation if isinstance(validation, dict) else {}
    for _ in range(3):
        if not isinstance(data, dict):
            break
        nested = None
        for key in ("api_response", "response", "result", "apiResponse", "Output"):
            if isinstance(data.get(key), dict):
                nested = data[key]
                break
        if nested is None:
            break
        data = nested
    return data, validation


def create_response(result, validation, passed=(), failed=(), errors=(), summary=None):
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error" if errors else "success", "errors": list(errors)},
            "validation": {"status": validation.get("status", "unknown"), "errors": validation.get("errors", []),
                           "warnings": validation.get("warnings", [])},
            "transformation": {"status": "success", "errors": [], "inputSummary": summary or {}},
            "evaluation": {"passReasons": list(passed), "failReasons": list(failed) + list(errors),
                           "recommendations": [], "additionalFindings": []},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0",
                         "transformationId": TRANSFORMATION_ID, "vendor": "Sophos", "category": CATEGORY},
        },
    }


def not_evaluated(reason, validation, summary=None):
    return create_response({CRITERIA_KEY: None}, validation, errors=[reason], summary=summary)


def number(value):
    """An int, also from a digit string (Token-Service may store every leaf as a string); else None."""
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    text = str(value).strip() if isinstance(value, str) else ""
    return int(text) if text.isdigit() else None


def flag(value):
    """True or False from a boolean or its string form; None for anything else."""
    if isinstance(value, bool):
        return value
    text = value.strip().lower() if isinstance(value, str) else ""
    return True if text == "true" else (False if text == "false" else None)


def partial_read(body, items):
    """Why the page read may not be the whole list; '' when it is."""
    pages = body.get("pages") if isinstance(body.get("pages"), dict) else {}
    current, total, size = number(pages.get("current")), number(pages.get("total")), number(pages.get("size"))
    if str(pages.get("nextKey") or "").strip().lower() not in ("", "none", "null"):
        return "another page follows"
    if total is not None and current is not None and total > current:
        return f"page {current} of {total}"
    if total is None and size and len(items) >= size:
        return f"a full page of {len(items)} with no page total"
    return ""


def transform(input):
    try:
        data, validation = extract_input(input)
        if validation.get("status") == "failed":
            return not_evaluated("Input validation failed: the Sophos firewall list was not read", validation)
        if not isinstance(data, dict) or "error" in data or "vendorErrorAsResponse" in data:
            return not_evaluated("Sophos did not return a firewall list (error or unrecognised body)", validation)
        items = data.get("items")
        if not isinstance(items, list):
            return not_evaluated("The Sophos firewall response carries no items array", validation)
        partial = partial_read(data, items)
        if partial:
            return not_evaluated("The Sophos firewall list was not read whole (" + partial + ")", validation)
        if not items:
            return not_evaluated("Sophos Central lists no firewalls, so there is nothing to measure", validation)

        counted = 0
        connected = 0
        auxiliary = 0
        auxiliary_offline = 0
        unreadable = 0
        for fw in items:
            status = fw.get("status") if isinstance(fw, dict) else None
            state = flag(status.get("connected")) if isinstance(status, dict) else None
            if state is None:
                unreadable = unreadable + 1
                continue
            cluster = fw.get("cluster")
            standby = isinstance(cluster, dict) and cluster.get("mode") == "activePassive"
            if standby and cluster.get("status") == "auxiliary":
                auxiliary = auxiliary + 1
                if not state:
                    auxiliary_offline = auxiliary_offline + 1
                continue
            counted = counted + 1
            if state:
                connected = connected + 1

        summary = {"firewalls": len(items), "counted": counted, "connected": connected,
                   "haAuxiliary": auxiliary, "haAuxiliaryOffline": auxiliary_offline,
                   "unreadable": unreadable}
        result = {CRITERIA_KEY: None, "totalFirewalls": counted, "connectedFirewalls": connected}
        if unreadable:
            return not_evaluated(f"{unreadable} of {len(items)} Sophos firewall(s) carry no boolean status.connected",
                                 validation, summary=summary)
        if not counted:
            return not_evaluated("Sophos Central lists only standby high-availability firewalls", validation,
                                 summary=summary)
        # A standby is excluded because the docs do not say whether it reports connected, and
        # that is an interpretation rather than a documented rule. Excluding a standby that
        # reports DISCONNECTED would turn the interpretation into an assertion: it could pass a
        # fleet whose standby is genuinely down. Measure what the docs support, and say
        # "not measured" for the case they do not cover.
        if auxiliary_offline:
            return not_evaluated(
                f"{auxiliary_offline} standby high-availability firewall(s) report status.connected false, and "
                "the Sophos documentation does not say whether a standby reports itself connected",
                validation, summary=summary)
        if connected < counted:
            result[CRITERIA_KEY] = False
            return create_response(result, validation, failed=[
                f"{counted - connected} of {counted} Sophos firewall(s) are not connected to Sophos Central "
                "(status.connected false)"], summary=summary)
        result[CRITERIA_KEY] = True
        return create_response(result, validation, passed=[
            f"All {counted} Sophos firewall(s) are connected to Sophos Central (status.connected true)"],
            summary=summary)
    except Exception as e:
        return not_evaluated("Transformation error: " + str(e)[:200], {"status": "error", "errors": [], "warnings": []})
