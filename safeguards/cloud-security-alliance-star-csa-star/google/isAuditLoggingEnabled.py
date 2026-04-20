"""
Transformation: isAuditLoggingEnabled
Vendor: Google  |  Category: cloud-security-alliance-star-csa-star
Evaluates: Whether admin audit logging is active and operational in the Google Workspace domain,
           confirmed by the presence of recent activity records in the Admin SDK Reports API response.
"""
import json
from datetime import datetime


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for _ in range(3):
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
            "dataCollection": {"status": "error" if (api_errors or []) else "success", "errors": api_errors or []},
            "validation": {"status": validation.get("status", "unknown"), "errors": validation.get("errors", []), "warnings": validation.get("warnings", [])},
            "transformation": {"status": "error" if (transformation_errors or []) else "success", "errors": transformation_errors or [], "inputSummary": input_summary or {}},
            "evaluation": {"passReasons": pass_reasons or [], "failReasons": fail_reasons or [], "recommendations": recommendations or [], "additionalFindings": additional_findings or []},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isAuditLoggingEnabled", "vendor": "Google", "category": "cloud-security-alliance-star-csa-star"}
        }
    }


def evaluate(data):
    """
    Checks the merged Admin SDK Reports API response (admin + login activities).
    Audit logging is considered enabled if the items array is non-empty, indicating
    that the domain is actively producing audit records.
    """
    try:
        items = data.get("items", [])
        if not isinstance(items, list):
            items = []

        total_items = len(items)

        admin_count = 0
        login_count = 0

        for item in items:
            item_id = item.get("id", {})
            if isinstance(item_id, dict):
                app_name = item_id.get("applicationName", "")
            else:
                app_name = ""
            if app_name == "admin":
                admin_count = admin_count + 1
            elif app_name == "login":
                login_count = login_count + 1

        is_enabled = total_items > 0

        return {
            "isAuditLoggingEnabled": is_enabled,
            "totalAuditRecords": total_items,
            "adminActivityRecords": admin_count,
            "loginActivityRecords": login_count
        }
    except Exception as e:
        return {"isAuditLoggingEnabled": False, "error": str(e)}


def transform(input):
    criteria_key = "isAuditLoggingEnabled"
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        if validation.get("status") == "failed":
            return create_response(
                result={criteria_key: False},
                validation=validation,
                fail_reasons=["Input validation failed"]
            )

        eval_result = evaluate(data)
        result_value = eval_result.get(criteria_key, False)

        extra_fields = {}
        for k in eval_result:
            if k != criteria_key and k != "error":
                extra_fields[k] = eval_result[k]

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        if result_value:
            pass_reasons.append("Audit logging is enabled — active audit records were found in the Admin SDK Reports API response.")
            pass_reasons.append("Total audit records found: " + str(extra_fields.get("totalAuditRecords", 0)))
            pass_reasons.append("Admin activity records: " + str(extra_fields.get("adminActivityRecords", 0)))
            pass_reasons.append("Login activity records: " + str(extra_fields.get("loginActivityRecords", 0)))
        else:
            fail_reasons.append("No audit activity records were found in the Admin SDK Reports API response.")
            if "error" in eval_result:
                fail_reasons.append("Evaluation error: " + eval_result["error"])
            recommendations.append("Verify that the Admin SDK Reports API is enabled in the Google Cloud Console and that the OAuth scopes include admin.reports.audit.readonly.")
            recommendations.append("Ensure that audit logging is active for the Google Workspace domain in the Admin console under Reports.")

        result_dict = {criteria_key: result_value}
        for k in extra_fields:
            result_dict[k] = extra_fields[k]

        summary_dict = {criteria_key: result_value}
        for k in extra_fields:
            summary_dict[k] = extra_fields[k]

        return create_response(
            result=result_dict,
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary=summary_dict
        )

    except Exception as e:
        return create_response(
            result={criteria_key: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
