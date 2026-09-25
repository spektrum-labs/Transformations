"""
Transformation: isEncryptionEnforced
Vendor: Sophos Central (Device Encryption)  |  Category: Endpoint Security
Method: getEndpoints (GET /endpoint/v1/endpoints)

Sophos reports per-computer disk encryption in endpoint.encryption:
  {"volumes": [{"volumeId", "status"}], "overallStatus"}
Volume statuses measured on 174 live endpoints across two production tenants on
2026-09-24: "encrypted", "notEncrypted", "suspended", "notSupported"; computers not
managed by Sophos Device Encryption carry no encryption block, or an empty volume list.

Scope is workstations (type == "computer"): the requirement is encryption of data on
media that leaves the building, which is laptops and desktops, not servers. Only
computers seen within 7 days of the newest lastSeenAt in the response are judged.

A computer counts as encrypted only when Sophos reports at least one volume and every
reported volume is "encrypted". A computer with no Sophos encryption report is NOT
counted as encrypted: it may be encrypted by other means, but Sophos does not prove it,
and the result says so separately from computers Sophos reports as unencrypted.

Verdict: true when at least one active computer exists and every one is encrypted.
The requirement token compares isEquals true.
"""
import json
from datetime import datetime, timedelta


ACTIVE_WINDOW_DAYS = 7

def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for attempt in range(3):
            unwrapped = False
            for key in wrapper_keys:
                if key in data and isinstance(data.get(key), (dict, list)):
                    data = data[key]
                    unwrapped = True
                    break
            if not unwrapped or not isinstance(data, dict):
                break
    return data, {"status": "unknown", "errors": [], "warnings": ["Legacy input format"]}


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, transformation_errors=None,
                    api_errors=None, additional_findings=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error" if (api_errors or []) else "success", "errors": api_errors or []},
            "validation": {"status": validation.get("status", "unknown"), "errors": validation.get("errors", []), "warnings": validation.get("warnings", [])},
            "transformation": {"status": "error" if (transformation_errors or []) else "success", "errors": transformation_errors or [], "inputSummary": input_summary or {}},
            "evaluation": {"passReasons": pass_reasons or [], "failReasons": fail_reasons or [], "recommendations": recommendations or [], "additionalFindings": additional_findings or []},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isEncryptionEnforced", "vendor": "Sophos", "category": "Endpoint Security"}
        }
    }


def endpoint_items(data):
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        items = data.get("items")
        if isinstance(items, list):
            return items
    return None


def api_error_message(data):
    if isinstance(data, dict) and (data.get("error") is True or str(data.get("error")).lower() == "true"):
        return str(data.get("errorMessage") or data.get("message") or "Sophos API returned an error")
    return None


def parse_seen(value):
    try:
        # strptime imports _strptime, which the Token-Service sandbox refuses.
        return datetime.fromisoformat(str(value)[:19])
    except Exception:
        return None


def active_endpoints(items):
    """Split endpoints into (active, stale_count) using the newest lastSeenAt as the clock."""
    endpoints = [e for e in items if isinstance(e, dict)]
    seen = [parse_seen(e.get("lastSeenAt")) for e in endpoints]
    known = [s for s in seen if s is not None]
    if not known:
        return endpoints, 0
    cutoff = max(known) - timedelta(days=ACTIVE_WINDOW_DAYS)
    active = []
    stale = 0
    for endpoint, when in zip(endpoints, seen):
        if when is not None and when < cutoff:
            stale = stale + 1
        else:
            active.append(endpoint)
    return active, stale




def encryption_state(endpoint):
    """Return "encrypted", "notEncrypted" or "unreported" for one computer."""
    volumes = (endpoint.get("encryption") or {}).get("volumes") or []
    volumes = [v for v in volumes if isinstance(v, dict)]
    if not volumes:
        return "unreported"
    if all(v.get("status") == "encrypted" for v in volumes):
        return "encrypted"
    return "notEncrypted"


def transform(input):
    criteriaKey = "isEncryptionEnforced"
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)
        if validation.get("status") == "failed":
            return create_response(result={criteriaKey: False}, validation=validation,
                                   fail_reasons=["Input validation failed"])

        error = api_error_message(data)
        items = endpoint_items(data)
        if error or items is None:
            reason = error or "Endpoints response not recognised - no items list present"
            return create_response(result={criteriaKey: False}, validation=validation,
                                   api_errors=[reason], fail_reasons=[reason],
                                   recommendations=["Verify the Sophos endpoints API (/endpoint/v1/endpoints) is reachable for this tenant"])

        active, stale = active_endpoints(items)
        computers = [e for e in active if e.get("type") == "computer"]
        encrypted = []
        not_encrypted = []
        unreported = []
        for endpoint in computers:
            host = endpoint.get("hostname") or endpoint.get("id") or "unknown"
            state = encryption_state(endpoint)
            if state == "encrypted":
                encrypted.append(host)
            elif state == "notEncrypted":
                not_encrypted.append(host)
            else:
                unreported.append(host)
        pct = round((len(encrypted) / len(computers)) * 100) if computers else 0
        value = len(computers) > 0 and len(encrypted) == len(computers)

        summary = {
            "activeComputers": len(computers),
            "encryptedComputers": len(encrypted),
            "encryptedPercentage": pct,
            "notEncryptedComputers": not_encrypted[:20],
            "encryptionNotReportedComputers": unreported[:20],
            "staleEndpointsExcluded": stale,
        }
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        if not computers:
            fail_reasons.append("No active computer was returned, so disk encryption could not be confirmed")
            recommendations.append("Check that the Sophos Central credential can read endpoints")
        elif value:
            pass_reasons.append(f"Sophos reports every volume encrypted on all {len(computers)} active computer(s)")
        else:
            if not_encrypted:
                fail_reasons.append(f"Sophos reports unencrypted or suspended volumes on {len(not_encrypted)} of {len(computers)} active computer(s)")
                recommendations.append("Complete or resume disk encryption on: " + ", ".join(str(h) for h in not_encrypted[:20]))
            if unreported:
                fail_reasons.append(f"Sophos reports no encryption status for {len(unreported)} of {len(computers)} active computer(s), so encryption is not proven for them")
                recommendations.append("Manage disk encryption for these computers with Sophos Device Encryption, or provide evidence from the tool that manages it")

        return create_response(result={criteriaKey: value, **summary}, validation=validation,
                               pass_reasons=pass_reasons, fail_reasons=fail_reasons,
                               recommendations=recommendations, input_summary={criteriaKey: value, **summary})
    except Exception as e:
        return create_response(result={criteriaKey: False},
                               validation={"status": "error", "errors": [], "warnings": []},
                               transformation_errors=[str(e)], fail_reasons=[f"Transformation error: {str(e)}"])
