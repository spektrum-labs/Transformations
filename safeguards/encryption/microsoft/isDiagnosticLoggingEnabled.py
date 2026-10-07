# isDiagnosticLoggingEnabled.py
# Azure Key Vault - LT-4.1: Security Investigation - Resource Logs Enabled
"""
isDiagnosticLoggingEnabled

Criterion: at least one diagnostic setting sends an enabled log category to a destination.

Data source: getDiagnosticSettings -- GET https://management.azure.com/{vaultResourceId}/providers
/Microsoft.Insights/diagnosticSettings?api-version=2021-05-01-preview
(https://learn.microsoft.com/en-us/rest/api/monitor/diagnostic-settings/list?view=rest-monitor-2021-05-01-preview).
The collection is {"value": [...]} with no paging. Each setting's properties.logs[] carries
category or categoryGroup and enabled; the destinations are workspaceId, storageAccountId,
eventHubAuthorizationRuleId and marketplacePartnerId. eventHubName alone is not a destination
("If none is specified, the default event hub will be selected" -- it needs the authorization
rule). An empty string is not a destination: the vendor's own example carries "workspaceId": "".

  true  = some setting has an enabled log and a non-empty destination
  false = the listing ran and no setting does (including no settings at all: a proven empty set)
  None  = no value list, an Azure error, or an exception

Every unmeasured path returns None, and respond() derives dataCollection.status from that value,
so an error body, an empty body or this file's own exception is Not evaluated, never a
measured false.
"""
import json
import ast
from datetime import datetime, timezone

KEY = "isDiagnosticLoggingEnabled"
VENDOR = "Microsoft Azure Key Vault"
CATEGORY = "Encryption"
METHOD = "getDiagnosticSettings"


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output", "rawResponse"]
        for i in range(3):
            unwrapped = False
            for key in wrapper_keys:
                if key in data and isinstance(data.get(key), dict):
                    data = data[key]
                    unwrapped = True
                    break
            if not unwrapped:
                break
    return data, {"status": "unknown", "errors": [], "warnings": ["Legacy input format"]}
DESTINATIONS = ["workspaceId", "storageAccountId", "eventHubAuthorizationRuleId", "marketplacePartnerId"]



def load(input):
    if isinstance(input, bytes):
        input = input.decode("utf-8")
    if isinstance(input, str):
        if not input.strip():
            input = None
        else:
            try:
                input = json.loads(input)
            except Exception:
                input = ast.literal_eval(input)
    return extract_input(input)


def respond(value, reason, validation=None, extra=None, recommendations=None, transformation_errors=None):
    """The one exit. Whether the criterion was measured is read off the value: None, and
    only None, is not measured, and that alone sets dataCollection.status to "error", which
    is what Token-Service reads to grade a criterion Not evaluated."""
    result = {KEY: value}
    for name in (extra or {}):
        result[name] = extra[name]
    measured = value is not None
    passed = value is True
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "success" if measured else "error", "errors": [] if measured else [reason]},
            "validation": {"status": validation.get("status", "unknown"), "errors": validation.get("errors", []),
                           "warnings": validation.get("warnings", [])},
            "transformation": {"status": "error" if transformation_errors else "success",
                               "errors": transformation_errors or [], "inputSummary": extra or {}},
            "evaluation": {"passReasons": [reason] if passed else [], "failReasons": [] if passed else [reason],
                           "recommendations": [] if passed else (recommendations or []), "additionalFindings": []},
            "metadata": {"evaluatedAt": datetime.now(timezone.utc).isoformat(), "schemaVersion": "2.0",
                         "transformationId": KEY, "vendor": VENDOR, "category": CATEGORY, "method": METHOD},
        },
    }


def error_reason(data):
    """Why this body is not an Azure answer, or None. Azure Resource Manager and the Key Vault
    data plane both fail with {"error": {"code": ..., "message": ...}}."""
    if not isinstance(data, dict):
        return "the response is not a JSON object"
    err = data.get("error")
    if err:
        if isinstance(err, dict):
            return "Azure returned an error: " + str(err.get("code") or "") + " " + str(err.get("message") or "")[:200]
        return "Azure returned an error: " + str(err)[:200]
    if data.get("errors") or data.get("vendorErrorAsResponse"):
        return "the response is an error envelope"
    status = data.get("statusCode") or data.get("status_code")
    if isinstance(status, int) and status >= 400:
        return "the response carries HTTP status " + str(status)
    return None


def listing(data, what):
    """(items, None) or (None, reason). A list response is {"value": [...], "nextLink": ...};
    only an explicit value list proves the listing ran."""
    items = data.get("value")
    if not isinstance(items, list):
        return None, "no value list in the response: the " + what + " were never listed"
    for item in items:
        if not isinstance(item, dict):
            return None, "an entry in the " + what + " list is not an object"
    return items, None


def next_link(data):
    link = data.get("nextLink") or data.get("@odata.nextLink")
    return link if isinstance(link, str) and link.strip() else None


def evaluate(data, validation):
    items, why = listing(data, "diagnostic settings")
    if why:
        return respond(None, why, validation)
    for item in items:
        props = item.get("properties")
        if not isinstance(props, dict):
            continue
        logs = props.get("logs")
        enabled = [log for log in (logs if isinstance(logs, list) else [])
                   if isinstance(log, dict) and log.get("enabled") is True]
        destinations = [field for field in DESTINATIONS if props.get(field)]
        if enabled and destinations:
            return respond(True, "Diagnostic setting " + str(item.get("name") or "?") + " sends "
                           + str(len(enabled)) + " enabled log categor(ies) to " + ", ".join(destinations),
                           validation, {"diagnosticSettingCount": len(items)})
    return respond(False, str(len(items)) + " diagnostic setting(s); none sends an enabled log category to a "
                   "destination", validation, {"diagnosticSettingCount": len(items)},
                   ["Add a diagnostic setting that sends Key Vault audit logs to Log Analytics, Storage or "
                    "Event Hubs"])


def transform(input):
    try:
        data, validation = load(input)
        why = error_reason(data)
        if why:
            return respond(None, why, validation)
        return evaluate(data, validation)
    except Exception as e:
        return respond(None, "Transformation error: " + str(e)[:300], None, {"error": str(e)[:300]},
                       transformation_errors=[str(e)[:300]])
