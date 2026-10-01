"""
Transformation: confirmedLicensePurchased
Vendor: Red Canary
Category: Cloud Security / Licensing

Evaluates if a valid Red Canary subscription is active.
Checks the audit_logs endpoint for a valid response indicating an active account.
"""

import json
from datetime import datetime


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for attempt in range(3):
            unwrapped = False
            for key in wrapper_keys:
                if key in data and isinstance(data.get(key), dict):
                    data = data[key]
                    unwrapped = True
                    break
            if not unwrapped:
                break
    return data, {"status": "unknown", "errors": [], "warnings": ["Legacy input format"]}


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, transformation_errors=None, api_errors=None, additional_findings=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {
                "status": "error" if (api_errors or []) else "success",
                "errors": api_errors or []
            },
            "validation": {
                "status": validation.get("status", "unknown"),
                "errors": validation.get("errors", []),
                "warnings": validation.get("warnings", [])
            },
            "transformation": {
                "status": "error" if (transformation_errors or []) else "success",
                "errors": transformation_errors or [],
                "inputSummary": input_summary or {}
            },
            "evaluation": {
                "passReasons": pass_reasons or [],
                "failReasons": fail_reasons or [],
                "recommendations": recommendations or [],
                "additionalFindings": additional_findings or []
            },
            "metadata": {
                "evaluatedAt": datetime.utcnow().isoformat() + "Z",
                "schemaVersion": "1.0",
                "transformationId": "confirmedLicensePurchased",
                "vendor": "Red Canary",
                "category": "Cloud Security"
            }
        }
    }


# ---- fail-closed guard (2026-10-01) ------------------------------------------------------------
# A body that does not show a measured answer proves nothing either way, so the criterion is
# returned as None with dataCollection.status "error". Token-Service reads that as Unevaluated:
# never a pass and never a finding. It covers a missing or empty body, a vendor or platform error
# envelope, a payload this transformation does not recognise, and a transformation exception.


def parse_body(data):
    """A JSON string or bytes body parsed; anything else unchanged. Unparseable text stays text."""
    if isinstance(data, bytes):
        try:
            data = data.decode("utf-8")
        except Exception:
            return data
    if isinstance(data, str):
        try:
            return json.loads(data)
        except Exception:
            return data
    return data


def error_problem(data):
    """Describe why `data` is a vendor or platform error rather than evidence, or return None."""
    if data is None:
        return "Red Canary returned no body"
    if isinstance(data, (str, bytes)):
        return "Red Canary returned a body that is not JSON"
    if not isinstance(data, dict):
        return None
    for name in ("statusCode", "status_code", "httpStatus", "vendorStatus"):
        code = data.get(name)
        if isinstance(code, str) and code.strip().isdigit():
            code = int(code.strip())
        if isinstance(code, int) and not isinstance(code, bool) and code >= 400:
            return "Red Canary returned HTTP " + str(code)
    err = data.get("error") or data.get("errors") or data.get("vendorError")
    if err:
        if isinstance(err, list):
            err = err[0]
        if isinstance(err, dict):
            err = err.get("message") or err.get("detail") or err.get("title") or err.get("type") or "error"
        return "Red Canary returned an error: " + str(err)[:200]
    if str(data.get("status", "")).strip().lower() == "error":
        return "the integration reported an error status"
    return None


def unevaluated(keys, problem, validation=None, input_summary=None, transformation_errors=None):
    """Every key as None plus a dataCollection error: reads Unevaluated, never True or False."""
    result = {}
    for key in keys:
        result[key] = None
    return create_response(
        result=result,
        validation=validation,
        fail_reasons=[problem],
        api_errors=[problem],
        transformation_errors=transformation_errors,
        input_summary=input_summary,
    )


def transform(input):
    criteriaKey = "confirmedLicensePurchased"

    try:
        data, validation = extract_input(parse_body(input))

        if isinstance(validation, dict) and validation.get("status") == "failed":
            return unevaluated([criteriaKey], "Input validation failed: nothing was measured", validation)

        problem = error_problem(data)
        if problem:
            return unevaluated([criteriaKey], problem, validation)

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        license_purchased = False
        license_details = {}

        if isinstance(data, dict):
            # Check for audit_logs response (array of audit log entries)
            audit_logs = data.get('audit_logs', data.get('data', []))
            if isinstance(audit_logs, list) and len(audit_logs) > 0:
                license_purchased = True
                license_details['auditLogCount'] = len(audit_logs)

            # Check for meta/pagination indicating valid response
            meta = data.get('meta', {})
            if isinstance(meta, dict) and ('total_count' in meta or 'total' in meta):
                license_purchased = True
                license_details['totalRecords'] = meta.get('total_count', meta.get('total'))

            # Check for subscription/account indicators
            if 'subscription' in data and data['subscription']:
                license_purchased = True
                license_details['subscription'] = data['subscription']
            elif 'account' in data and data['account']:
                license_purchased = True

            # Fallback: valid org data with an ID indicates active account
            if not license_purchased and data.get('id'):
                license_purchased = True
                license_details['accountId'] = data.get('id')

            # The old final fallback -- "if not license_purchased and len(data) > 0:
            # license_purchased = True" -- treated ANY non-empty dict as proof the
            # subscription was active, so an auth-error envelope or an unrecognised body
            # with any key at all satisfied the criterion. Removed: the response must
            # actually contain audit logs, pagination totals, a subscription/account
            # indicator, or an account id.

        elif isinstance(data, list):
            if len(data) > 0:
                license_purchased = True
                license_details['auditLogCount'] = len(data)

        if not license_purchased:
            # An empty audit log, an empty list or a body with none of the indicators above is
            # not a measurement of the subscription: Unevaluated, never a finding.
            return unevaluated(
                [criteriaKey],
                "The response carries no audit log records or account indicator: the "
                "subscription could not be read, so nothing was measured",
                validation)

        pass_reasons.append("Red Canary subscription is active and confirmed")

        return create_response(
            result={criteriaKey: license_purchased, **license_details},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={"licensePurchased": license_purchased, **license_details}
        )

    except Exception as e:
        message = "Transformation error: " + str(e)[:200]
        return unevaluated([criteriaKey], message, {"status": "error", "errors": [], "warnings": []},
                           transformation_errors=[message])
