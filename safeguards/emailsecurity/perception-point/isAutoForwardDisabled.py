"""
Transformation: isAutoForwardDisabled
Vendor: Perception Point  |  Category: emailsecurity
Evaluates: Auto-forwarding controls are enforced at the email provider level and
are not directly exposed via the Perception Point API. Evaluates outbound scan
traffic in scan records for auto-forwarding patterns. Absence of systematic
auto-forwarded message patterns in outbound scans serves as a proxy indicator
that auto-forwarding is disabled.
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isAutoForwardDisabled", "vendor": "Perception Point", "category": "emailsecurity"}
        }
    }


def evaluate(data):
    try:
        scans = data.get("scans", [])
        if not isinstance(scans, list):
            scans = []
        scan_count = len(scans)
        auto_forward_indicators = 0
        for scan in scans:
            if not isinstance(scan, dict):
                continue
            channel = str(scan.get("channel", "")).lower()
            if "forward" in channel or "autoforward" in channel:
                auto_forward_indicators = auto_forward_indicators + 1
                continue
            sender = scan.get("sender", {})
            sender_str = str(sender).lower() if isinstance(sender, dict) else str(sender).lower()
            if "forward" in sender_str and "auto" in sender_str:
                auto_forward_indicators = auto_forward_indicators + 1
                continue
            scanner_results = scan.get("scanner_results", {})
            if isinstance(scanner_results, dict):
                scanner_str = str(scanner_results).lower()
                if "autoforward" in scanner_str or ("auto" in scanner_str and "forward" in scanner_str):
                    auto_forward_indicators = auto_forward_indicators + 1
        is_disabled = scan_count > 0 and auto_forward_indicators == 0
        return {
            "isAutoForwardDisabled": is_disabled,
            "totalScans": scan_count,
            "autoForwardIndicatorsFound": auto_forward_indicators
        }
    except Exception as e:
        return {"isAutoForwardDisabled": False, "error": str(e)}


def transform(input):
    criteria_key = "isAutoForwardDisabled"
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
            pass_reasons.append("No auto-forwarding patterns detected in Perception Point outbound scan records, indicating auto-forwarding is disabled")
            total = extra_fields.get("totalScans", 0)
            pass_reasons.append("Total scans evaluated: " + str(total))
        else:
            indicators = extra_fields.get("autoForwardIndicatorsFound", 0)
            total = extra_fields.get("totalScans", 0)
            if total == 0:
                fail_reasons.append("No scan records found to evaluate auto-forwarding traffic patterns")
            elif indicators > 0:
                fail_reasons.append("Auto-forwarding indicators detected in " + str(indicators) + " scan record(s)")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Disable automatic email forwarding at the email service provider level to prevent data exfiltration via forwarding rules")
        additional_findings.append("Auto-forwarding controls are enforced at the email provider level; Perception Point outbound scan data provides a secondary validation signal")
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
