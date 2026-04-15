"""
Transformation: isAuditLoggingEnabled
Vendor: Duo  |  Category: iam
Evaluates: Validate that audit logging is enabled and actively capturing both
           authentication events and administrator action events via the Duo logs API.
"""
import json
from datetime import datetime


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
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


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, transformation_errors=None,
                    api_errors=None, additional_findings=None):
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
                "transformationId": "isAuditLoggingEnabled",
                "vendor": "Duo",
                "category": "iam"
            }
        }
    }


def find_log_data(data):
    """Find authentication and admin log arrays from merged API response."""
    auth_logs = None
    admin_logs = None

    if not isinstance(data, dict):
        if isinstance(data, list):
            auth_logs = data
        return auth_logs, admin_logs

    # Direct top-level keys from Duo getAuthLogs endpoint
    if "authlogs" in data:
        val = data.get("authlogs")
        if isinstance(val, list):
            auth_logs = val

    # Direct top-level keys from Duo getAdminLogs endpoint
    if "items" in data:
        val = data.get("items")
        if isinstance(val, list):
            admin_logs = val

    # Nested response object if not yet found
    response_obj = data.get("response")
    if isinstance(response_obj, dict):
        if auth_logs is None:
            val = response_obj.get("authlogs")
            if isinstance(val, list):
                auth_logs = val
        if admin_logs is None:
            val = response_obj.get("items")
            if isinstance(val, list):
                admin_logs = val

    # Fallback: returnSpec maps both to "data" — last one may have overwritten the other
    if auth_logs is None and admin_logs is None:
        val = data.get("data")
        if isinstance(val, list):
            auth_logs = val

    return auth_logs, admin_logs


def evaluate(data):
    """Core evaluation logic for isAuditLoggingEnabled."""
    try:
        if isinstance(data, dict) and data.get("stat") == "FAIL":
            msg = data.get("message", "Duo API returned FAIL status")
            return {
                "isAuditLoggingEnabled": False,
                "error": msg,
                "authLoggingActive": False,
                "adminLoggingActive": False,
                "authLogCount": 0,
                "adminLogCount": 0,
                "totalLogEntries": 0
            }

        auth_logs, admin_logs = find_log_data(data)

        has_auth_logging = auth_logs is not None
        has_admin_logging = admin_logs is not None
        auth_log_count = len(auth_logs) if has_auth_logging else 0
        admin_log_count = len(admin_logs) if has_admin_logging else 0
        total = auth_log_count + admin_log_count

        # Logging is enabled if at least one endpoint returned a valid (even empty) list
        is_enabled = has_auth_logging or has_admin_logging

        return {
            "isAuditLoggingEnabled": is_enabled,
            "authLoggingActive": has_auth_logging,
            "adminLoggingActive": has_admin_logging,
            "bothSourcesActive": has_auth_logging and has_admin_logging,
            "authLogCount": auth_log_count,
            "adminLogCount": admin_log_count,
            "totalLogEntries": total
        }
    except Exception as e:
        return {"isAuditLoggingEnabled": False, "error": str(e)}


def transform(input):
    criteriaKey = "isAuditLoggingEnabled"
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))
        data, validation = extract_input(input)
        if validation.get("status") == "failed":
            return create_response(
                result={criteriaKey: False},
                validation=validation,
                fail_reasons=["Input validation failed"]
            )

        eval_result = evaluate(data)
        result_value = eval_result.get(criteriaKey, False)

        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []

        auth_count = eval_result.get("authLogCount", 0)
        admin_count = eval_result.get("adminLogCount", 0)
        total = eval_result.get("totalLogEntries", 0)
        both_active = eval_result.get("bothSourcesActive", False)
        has_auth = eval_result.get("authLoggingActive", False)
        has_admin = eval_result.get("adminLoggingActive", False)

        if result_value:
            pass_reasons.append("Duo audit logging is active and returning valid log data")
            if both_active:
                pass_reasons.append("Both authentication event logs and administrator action logs are confirmed active")
            pass_reasons.append("Authentication log entries in queried window: " + str(auth_count))
            pass_reasons.append("Administrator action log entries in queried window: " + str(admin_count))
        else:
            fail_reasons.append("Audit logging does not appear to be enabled or returning valid data from either log endpoint")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Ensure the Duo Admin API integration has the Grant read log permission enabled")
            recommendations.append("Verify that /admin/v2/logs/authentication and /admin/v2/logs/administrator endpoints are accessible with current credentials")

        if not has_auth:
            additional_findings.append("Authentication log endpoint returned no valid list data")
        if not has_admin:
            additional_findings.append("Administrator action log endpoint returned no valid list data")
        if total > 0:
            additional_findings.append("Total log entries retrieved in queried window: " + str(total))

        result_dict = {criteriaKey: result_value}
        result_dict["authLoggingActive"] = has_auth
        result_dict["adminLoggingActive"] = has_admin
        result_dict["bothSourcesActive"] = both_active
        result_dict["authLogCount"] = auth_count
        result_dict["adminLogCount"] = admin_count
        result_dict["totalLogEntries"] = total

        return create_response(
            result=result_dict,
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={criteriaKey: result_value, "totalLogEntries": total}
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
