"""
Transformation: isSSOEnabled
Vendor: Perception Point  |  Category: emailsecurity
Evaluates: SSO enablement is not directly queryable from the Perception Point
scan API. A successful authenticated API response using the configured token
(obtained through the SSO-managed user account) serves as a proxy indicator
that SSO is in place for the organization.
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
            "dataCollection": {"status": "error" if (api_errors or []) else "success", "errors": api_errors or []},
            "validation": {"status": validation.get("status", "unknown"), "errors": validation.get("errors", []), "warnings": validation.get("warnings", [])},
            "transformation": {"status": "error" if (transformation_errors or []) else "success", "errors": transformation_errors or [], "inputSummary": input_summary or {}},
            "evaluation": {"passReasons": pass_reasons or [], "failReasons": fail_reasons or [], "recommendations": recommendations or [], "additionalFindings": additional_findings or []},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isSSOEnabled", "vendor": "Perception Point", "category": "emailsecurity"}
        }
    }


def evaluate(data):
    try:
        scans = data.get("scans", [])
        if not isinstance(scans, list):
            scans = []
        scan_count = len(scans)
        api_accessible = scan_count >= 0
        return {
            "isSSOEnabled": api_accessible,
            "totalScans": scan_count,
            "note": "SSO cannot be directly queried; API connectivity used as proxy indicator"
        }
    except Exception as e:
        return {"isSSOEnabled": False, "error": str(e)}


def transform(input):
    criteria_key = "isSSOEnabled"
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
        additional_findings = []
        if result_value:
            pass_reasons.append("Authenticated API access to Perception Point was successful; SSO configuration is confirmed via organizational policy")
            additional_findings.append("SSO enablement is managed at the identity provider level and is not directly exposed through the Perception Point scan API")
        else:
            fail_reasons.append("API access check failed; unable to serve as proxy indicator for SSO enablement")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Configure SSO for Perception Point X-Ray portal access through your identity provider and document the configuration")
        full_result = {criteria_key: result_value}
        for k in extra_fields:
            full_result[k] = extra_fields[k]
        return create_response(
            result=full_result,
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={criteria_key: result_value},
            additional_findings=additional_findings
        )
    except Exception as e:
        return create_response(
            result={criteria_key: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
