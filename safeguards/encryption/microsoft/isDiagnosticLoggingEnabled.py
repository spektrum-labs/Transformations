"""
Transformation: isDiagnosticLoggingEnabled
Vendor: Microsoft Azure Key Vault  |  Category: Encryption

Criterion: vault resource logs are collected to a destination.

Data source:
    getDiagnosticSettings -- GET https://management.azure.com/{vaultResourceId}/providers/
    Microsoft.Insights/diagnosticSettings?api-version=2021-05-01-preview, a {"value": [...]} list
    (https://learn.microsoft.com/en-us/rest/api/monitor/diagnostic-settings/list)

  isDiagnosticLoggingEnabled = true when one setting has a log category enabled and a destination
  (workspaceId, storageAccountId, eventHubAuthorizationRuleId or eventHubName); false when the
  listed settings (possibly none) have no such pair. ARM answers 403 on a scope it cannot read,
  so an empty `value` here is a proven empty list, not silence.

Not evaluated (None, dataCollection status "error"): an ARM or Key Vault error envelope at the
top level or inside a response/result/apiResponse wrapper, a body of the wrong shape, or this
transform's own exception. An error is not a failed control, so it is never a measured False.
"""
import json
import ast
from datetime import datetime

KEY = "isDiagnosticLoggingEnabled"
VENDOR = "Microsoft Azure Key Vault"
CATEGORY = "Encryption"

WRAPPER_KEYS = ["api_response", "response", "result", "apiResponse", "Output", "rawResponse", "data"]


def parse_input(input):
    if isinstance(input, bytes):
        input = input.decode("utf-8")
    if isinstance(input, str):
        text = input.strip()
        if not text:
            return None
        try:
            return json.loads(text)
        except ValueError:
            return ast.literal_eval(text)
    return input


def error_message(body):
    """The error an ARM or Key Vault error envelope carries, or None for any other body."""
    if not isinstance(body, dict):
        return None
    error = body.get("error") or body.get("errors")
    if isinstance(error, dict):
        parts = [str(error.get(name)) for name in ("code", "message") if error.get(name)]
        return (": ".join(parts) or "error")[:300]
    if isinstance(error, str):
        return error[:300]
    if error:
        return str(body.get("errorType") or body.get("message") or "error")[:300]
    status = body.get("statusCode") or body.get("status_code") or body.get("status")
    if isinstance(status, str) and status.strip().isdigit():
        status = int(status.strip())
    if isinstance(status, int) and not isinstance(status, bool) and status >= 400:
        return ("HTTP " + str(status) + " " + str(body.get("message") or "")).strip()
    return None


def unwrap(data):
    """Peel the integration's wrappers. Returns (body, error); an error at any level wins."""
    for i in range(5):
        message = error_message(data)
        if message:
            return data, message
        if not isinstance(data, dict):
            return data, None
        inner = None
        for name in WRAPPER_KEYS:
            if isinstance(data.get(name), dict):
                inner = data[name]
                break
        if inner is None:
            return data, None
        data = inner
    return data, error_message(data)


def create_response(result, pass_reasons=None, fail_reasons=None, recommendations=None,
                    input_summary=None, api_errors=None, transformation_errors=None):
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error" if (api_errors or []) else "success", "errors": api_errors or []},
            "validation": {"status": "unknown", "errors": [], "warnings": []},
            "transformation": {"status": "error" if (transformation_errors or []) else "success",
                               "errors": transformation_errors or [], "inputSummary": input_summary or {}},
            "evaluation": {"passReasons": pass_reasons or [], "failReasons": fail_reasons or [],
                           "recommendations": recommendations or [], "additionalFindings": []},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "2.0",
                         "transformationId": KEY, "vendor": VENDOR, "category": CATEGORY},
        },
    }


def not_measured(reason, input_summary=None):
    return create_response(result={KEY: None}, api_errors=[reason], fail_reasons=[reason],
                           input_summary=input_summary)


def measured(passed, line, recommendation, input_summary=None):
    if passed:
        return create_response(result={KEY: True}, pass_reasons=[line], input_summary=input_summary)
    return create_response(result={KEY: False}, fail_reasons=[line], recommendations=[recommendation],
                           input_summary=input_summary)


def transform(input):
    try:
        data, error = unwrap(parse_input(input))
        if error:
            return not_measured("The Azure API returned an error: " + error)
        settings = data.get("value") if isinstance(data, dict) else None
        if not isinstance(settings, list):
            return not_measured("No `value` list in the diagnostic settings response, so the settings were "
                                "never listed")
        for setting in settings:
            properties = setting.get("properties") if isinstance(setting, dict) else None
            if not isinstance(properties, dict):
                continue
            logs = properties.get("logs") or []
            has_enabled_log = False
            for log in logs if isinstance(logs, list) else []:
                if isinstance(log, dict) and log.get("enabled") is True:
                    has_enabled_log = True
                    break
            has_destination = (properties.get("workspaceId") or properties.get("storageAccountId")
                               or properties.get("eventHubAuthorizationRuleId") or properties.get("eventHubName"))
            if has_enabled_log and has_destination:
                return measured(True, "Diagnostic setting " + str(setting.get("name") or "")
                                + " sends enabled log categories to a destination", None,
                                {"settingCount": len(settings)})
        return measured(False, "No diagnostic setting among " + str(len(settings))
                        + " sends an enabled log category to a destination",
                        "Add a diagnostic setting that sends the AuditEvent logs to Log Analytics, storage or "
                        "Event Hubs", {"settingCount": len(settings)})
    except Exception as e:
        return create_response(result={KEY: None}, transformation_errors=[str(e)],
                               api_errors=["Transformation error: " + str(e)],
                               fail_reasons=["Transformation error: " + str(e)])
