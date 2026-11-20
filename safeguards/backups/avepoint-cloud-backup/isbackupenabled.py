"""Transformation: isBackupEnabled
Vendor: AvePoint  |  Category: Backups  |  Product: AvePoint Cloud Backup for Microsoft 365
Method: getBackupFrequency

  GET {serverUrl}/backup/m365/settings/backup/frequency
  Permission: microsoft365backup.settings.read.all
  https://learn.avepoint.com/docs/services-and-features/m365/backup-frequency.html

Documented body: {"statusCode": 200, "message": "", "data": [{"serviceType": <int>, "frequency": <int>,
"backupStartTime": ["<UTC ISO 8601>", ...]}, ...], "requestId", "timestamp", "traceId"}. "data" is the
backup frequency of every ACTIVE Microsoft 365 service (serviceType codes: Overview > Attribute: serviceType,
https://learn.avepoint.com/docs/services-and-features/m365/overview.html).

True when at least one service is listed with a backup frequency of one or more jobs a day: Cloud Backup is
switched on for that service. False when the settings were read and no service is listed, or every listed
service has frequency 0. None (Unevaluated) for a missing, error, vendorErrorAsResponse, truncated or
unrecognised body, or when no service is active but some entry could not be read.

Scope: without the location parameter AvePoint returns the central AOS location only, so a Multi-Geo
tenant's satellite locations are not read; the reason says so.
Proves: backup is configured and scheduled for at least one Microsoft 365 service.
Does not prove: that the jobs succeed, or that every service is covered (see isBackupTypesScheduled).
"""

import json
from datetime import datetime, timezone

KEY = "isBackupEnabled"
METHOD = "getBackupFrequency"
ENDPOINT = "GET /backup/m365/settings/backup/frequency"
VENDOR = "AvePoint Cloud Backup for Microsoft 365"
CATEGORY = "Backups"
REQUIRED_PERMISSION = "microsoft365backup.settings.read.all"
WRAPPER_KEYS = ["apiResponse", "api_response", "response", "result", "Output", "_response_data"]
SERVICE_NAMES = {0: "Exchange Online", 1: "SharePoint Online", 2: "OneDrive", 3: "Microsoft 365 Groups",
                 4: "Project Online", 5: "Public Folder", 6: "Teams", 7: "Public Folder Metadata",
                 8: "Private Channel", 9: "Yammer Group", 10: "Personal Chat", 11: "Power BI",
                 12: "Power Automate", 13: "Shared Channel", 14: "Power Apps"}
SCOPE_NOTE = ("Read from the central AOS location only (no location parameter); Multi-Geo satellite "
              "locations are not included.")


def decode(value):
    """A body as an object: dicts and lists as they are, JSON text or bytes parsed, else None."""
    if isinstance(value, bytes):
        try:
            value = value.decode("utf-8")
        except Exception:
            return None
    if isinstance(value, str):
        try:
            return json.loads(value)
        except Exception:
            return None
    return value


def unwrap(value):
    """Strip the Integration-Service / Token-Service envelopes; the AvePoint body is left as it is."""
    value = decode(value)
    for step in range(5):
        if not isinstance(value, dict):
            return value
        if "validation" in value and "data" in value and isinstance(value.get("validation"), dict):
            value = decode(value.get("data"))
            continue
        moved = False
        for key in WRAPPER_KEYS:
            inner = value.get(key)
            if isinstance(inner, (dict, list, str, bytes)) and inner not in ("", b""):
                inner = decode(inner)
                if isinstance(inner, (dict, list)):
                    value = inner
                    moved = True
                    break
        if not moved:
            return value
    return value


def as_int(value):
    """An int that is not a bool, else None."""
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


def service_name(code):
    if code in SERVICE_NAMES:
        return SERVICE_NAMES[code]
    return "serviceType " + str(code)[:10]


def vendor_problem(body):
    """Why this body is not evidence (a dict with status and text), or None when it is a successful read."""
    if not isinstance(body, dict):
        return None
    marker = body.get("vendorErrorAsResponse")
    if marker is not None:
        status = marker.get("status") if isinstance(marker, dict) else None
        return {"status": status, "text": "AvePoint refused the call"}
    if body.get("error") not in (None, False, "", 0):
        status = as_int(body.get("statusCode")) or as_int(body.get("status_code")) or as_int(body.get("status"))
        return {"status": status, "text": "Integration-Service returned an error for the call"}
    if body.get("paginationTruncated") is True:
        return {"status": None, "text": "the read was cut short (paginationTruncated)"}
    status = as_int(body.get("statusCode"))
    if "statusCode" in body and status != 200:
        return {"status": status, "text": "AvePoint answered with statusCode " + str(body.get("statusCode"))[:10]}
    errors = body.get("errors")
    if isinstance(errors, list) and len(errors) > 0:
        return {"status": status, "text": "AvePoint returned " + str(len(errors)) + " API error(s)"}
    return None


def create_response(result, pass_reasons=None, fail_reasons=None, recommendations=None,
                    input_summary=None, api_errors=None, additional_findings=None):
    api_err_list = api_errors or []
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error" if api_err_list else "success", "errors": api_err_list},
            "validation": {"status": "unknown", "errors": [], "warnings": []},
            "transformation": {"status": "success", "errors": [], "inputSummary": input_summary or {}},
            "evaluation": {
                "passReasons": pass_reasons or [],
                "failReasons": fail_reasons or [],
                "recommendations": recommendations or [],
                "additionalFindings": additional_findings or [],
            },
            "metadata": {
                "evaluatedAt": datetime.now(timezone.utc).replace(tzinfo=None).isoformat() + "Z",
                "schemaVersion": "2.0",
                "transformationId": KEY,
                "vendor": VENDOR,
                "category": CATEGORY,
                "method": METHOD,
            },
        },
    }


def not_evaluated(reason, problem=None):
    """Nothing was measured: the key is None (Unevaluated), never True and never False."""
    text = "Not evaluated: " + reason
    out = create_response({KEY: None}, fail_reasons=[text], api_errors=[text])
    status = problem.get("status") if isinstance(problem, dict) else None
    if status in (401, 403):
        out["additionalInfo"]["dataCollection"]["errorCode"] = "permission_not_granted"
        out["additionalInfo"]["dataCollection"]["requiredPermission"] = REQUIRED_PERMISSION
        out["additionalInfo"]["evaluation"]["recommendations"] = [
            "In AvePoint Online Services open Administration > App registrations, edit the Spektrum app and add "
            "the Cloud Backup for Microsoft 365 permission " + REQUIRED_PERMISSION + "."]
    return out


def read_frequency(input):
    """(entries, None) for a complete documented body, else (None, (reason, problem))."""
    body = unwrap(input)
    if not isinstance(body, dict):
        return None, ("no " + ENDPOINT + " response was returned", None)
    problem = vendor_problem(body)
    if problem is not None:
        return None, (problem["text"] + " (" + ENDPOINT + "); nothing was measured.", problem)
    if as_int(body.get("statusCode")) != 200:
        return None, ("the " + ENDPOINT + " response has no statusCode 200, so it is not the documented body", None)
    entries = body.get("data")
    if not isinstance(entries, list):
        return None, ("the " + ENDPOINT + " response carries no data list", None)
    return entries, None


def measure(input):
    entries, failure = read_frequency(input)
    if entries is None:
        return not_evaluated(failure[0], failure[1])
    active = []
    inactive = []
    unreadable = 0
    for entry in entries:
        if not isinstance(entry, dict):
            unreadable = unreadable + 1
            continue
        code = as_int(entry.get("serviceType"))
        frequency = as_int(entry.get("frequency"))
        if code is None or frequency is None or frequency < 0:
            unreadable = unreadable + 1
            continue
        if frequency >= 1:
            active.append(service_name(code) + " (" + str(frequency) + " a day)")
        else:
            inactive.append(service_name(code))
    summary = {"servicesListed": len(entries), "servicesWithBackup": len(active),
               "servicesWithZeroFrequency": len(inactive), "unreadableEntries": unreadable}
    if active:
        result = {KEY: True, "servicesWithBackup": active[:20]}
        return create_response(result, pass_reasons=["Cloud Backup runs for " + str(len(active)) + " Microsoft 365 "
                                                     "service(s): " + ", ".join(active[:10]) + ". " + SCOPE_NOTE],
                               input_summary=summary)
    if unreadable > 0:
        return not_evaluated(str(unreadable) + " backup frequency entr(y/ies) could not be read and no service was "
                             "readable as backed up.")
    if not entries:
        reason = "AvePoint lists no active Microsoft 365 service with a backup frequency, so Cloud Backup is not running."
    else:
        reason = ("Every listed service has a backup frequency of 0: " + ", ".join(inactive[:10]) + ".")
    return create_response({KEY: False}, fail_reasons=[reason + " " + SCOPE_NOTE],
                           recommendations=["In AvePoint Cloud Backup for Microsoft 365 add the services and objects "
                                            "to protect (Exchange Online, SharePoint Online, OneDrive, Teams, ...) so "
                                            "they are backed up on the automatic schedule."],
                           input_summary=summary)


def transform(input):
    try:
        return measure(input)
    except Exception:
        return not_evaluated("the backup frequency response could not be processed")
