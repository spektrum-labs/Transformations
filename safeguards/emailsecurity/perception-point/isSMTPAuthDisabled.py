"""
Transformation: isSMTPAuthDisabled
Vendor: Perception Point  |  Category: emailsecurity
Evaluates: SMTP AUTH disablement is configured at the email gateway or provider
level. Evaluates Perception Point scan records for the presence of SMTP
AUTH-sourced traffic. Absence of such traffic within scan logs serves as an
indicator that SMTP AUTH is disabled at the sending domain.
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isSMTPAuthDisabled", "vendor": "Perception Point", "category": "emailsecurity"}
        }
    }


def evaluate(data):
    try:
        scans = data.get("scans", [])
        if not isinstance(scans, list):
            scans = []
        scan_count = len(scans)
        smtp_auth_indicators = 0
        for scan in scans:
            if not isinstance(scan, dict):
                continue
            channel = str(scan.get("channel", "")).lower()
            if "smtp_auth" in channel or "smtpauth" in channel:
                smtp_auth_indicators = smtp_auth_indicators + 1
                continue
            sender = scan.get("sender", {})
            if isinstance(sender, dict):
                sender_str = str(sender).lower()
                if "smtp_auth" in sender_str or "smtpauth" in sender_str:
                    smtp_auth_indicators = smtp_auth_indicators + 1
        is_disabled = scan_count > 0 and smtp_auth_indicators == 0
        return {
            "isSMTPAuthDisabled": is_disabled,
            "totalScans": scan_count,
            "smtpAuthIndicatorsFound": smtp_auth_indicators
        }
    except Exception as e:
        return {"isSMTPAuthDisabled": False, "error": str(e)}


def transform(input):
    criteria_key = "isSMTPAuthDisabled"
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
            pass_reasons.append("No SMTP AUTH traffic detected in Perception Point scan records, indicating SMTP AUTH is disabled at the email provider level")
            total = extra_fields.get("totalScans", 0)
            pass_reasons.append("Total scans evaluated: " + str(total))
        else:
            indicators = extra_fields.get("smtpAuthIndicatorsFound", 0)
            total = extra_fields.get("totalScans", 0)
            if total == 0:
                fail_reasons.append("No scan records found to evaluate SMTP AUTH traffic patterns")
            elif indicators > 0:
                fail_reasons.append("SMTP AUTH traffic indicators detected in " + str(indicators) + " scan record(s)")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Disable SMTP AUTH at the email service provider level to prevent credential-based SMTP relay abuse")
        additional_findings.append("SMTP AUTH disablement is configured at the email gateway or provider level; Perception Point scan data provides a secondary validation signal")
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
