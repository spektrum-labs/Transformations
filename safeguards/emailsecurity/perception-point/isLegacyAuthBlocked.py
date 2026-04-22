"""
Transformation: isLegacyAuthBlocked
Vendor: Perception Point  |  Category: emailsecurity
Evaluates: Legacy authentication blocking is enforced at the email service provider
level (e.g. Microsoft 365 or Google Workspace). Perception Point scan data is used
to confirm the integration is operating in an environment where legacy auth protocols
are not present in scanned traffic.
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isLegacyAuthBlocked", "vendor": "Perception Point", "category": "emailsecurity"}
        }
    }


def evaluate(data):
    try:
        scans = data.get("scans", [])
        if not isinstance(scans, list):
            scans = []
        scan_count = len(scans)
        legacy_auth_indicators = 0
        for scan in scans:
            if not isinstance(scan, dict):
                continue
            scanner_results = scan.get("scanner_results", {})
            if isinstance(scanner_results, dict):
                scanner_str = str(scanner_results).lower()
                if "legacy" in scanner_str and "auth" in scanner_str:
                    legacy_auth_indicators = legacy_auth_indicators + 1
            channel = scan.get("channel", "")
            if "smtp" in str(channel).lower() and "legacy" in str(channel).lower():
                legacy_auth_indicators = legacy_auth_indicators + 1
        is_blocked = scan_count > 0 and legacy_auth_indicators == 0
        return {
            "isLegacyAuthBlocked": is_blocked,
            "totalScans": scan_count,
            "legacyAuthIndicatorsFound": legacy_auth_indicators
        }
    except Exception as e:
        return {"isLegacyAuthBlocked": False, "error": str(e)}


def transform(input):
    criteria_key = "isLegacyAuthBlocked"
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
            pass_reasons.append("No legacy authentication indicators detected in Perception Point scan traffic, suggesting legacy auth is blocked at the email provider level")
            total = extra_fields.get("totalScans", 0)
            pass_reasons.append("Total scans evaluated: " + str(total))
        else:
            indicators = extra_fields.get("legacyAuthIndicatorsFound", 0)
            total = extra_fields.get("totalScans", 0)
            if total == 0:
                fail_reasons.append("No scan records found to evaluate legacy authentication traffic patterns")
            elif indicators > 0:
                fail_reasons.append("Legacy authentication indicators found in " + str(indicators) + " scan record(s)")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Block legacy authentication protocols at the email service provider level (e.g. disable Basic Auth in Microsoft 365 or Google Workspace)")
        additional_findings.append("Legacy authentication blocking is enforced at the email service provider level; Perception Point scan data serves as a secondary validation signal")
        full_result = {criteria_key: result_value}
        for k in extra_fields:
            full_result[k] = extra_fields[k]
        return create_response(
            result=full_result,
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary=full_result,
            additional_findings=additional_findings
        )
    except Exception as e:
        return create_response(
            result={criteria_key: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
