"""
Transformation: isSPFConfigured
Vendor: Sophos  |  Category: control-objectives-for-information-and-related-technologies-cobit
Evaluates: Check for evidence of SPF record configuration by scanning Sophos Central alerts
for email security events related to SPF validation and an SPF record being published.
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isSPFConfigured", "vendor": "Sophos", "category": "control-objectives-for-information-and-related-technologies-cobit"}
        }
    }


def evaluate(data):
    try:
        items = data.get("items", [])
        total_alerts = len(items)
        spf_events = []
        for alert in items:
            description = alert.get("description", "").lower()
            alert_type = alert.get("type", "").lower()
            category = alert.get("category", "").lower()
            product = alert.get("product", "").lower()
            if "spf" in description or "spf" in alert_type or "spf" in category or "spf" in product:
                spf_events.append(alert.get("id", "unknown"))
        is_configured = len(spf_events) > 0
        return {
            "isSPFConfigured": is_configured,
            "totalAlerts": total_alerts,
            "spfEventCount": len(spf_events),
            "spfEventIds": spf_events[:10],
            "note": "SPF configuration is a DNS-level control; Sophos alerts provide indirect evidence only"
        }
    except Exception as e:
        return {"isSPFConfigured": False, "error": str(e)}


def transform(input):
    criteriaKey = "isSPFConfigured"
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))
        data, validation = extract_input(input)
        if validation.get("status") == "failed":
            return create_response(result={criteriaKey: False}, validation=validation, fail_reasons=["Input validation failed"])
        eval_result = evaluate(data)
        result_value = eval_result.get(criteriaKey, False)
        extra_fields = {k: v for k, v in eval_result.items() if k != criteriaKey and k != "error"}
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = [extra_fields.get("note", "")]
        result_dict = {criteriaKey: result_value}
        for k in extra_fields:
            result_dict[k] = extra_fields[k]
        if result_value:
            pass_reasons.append("SPF-related email security events found in Sophos Central alerts")
            pass_reasons.append("spfEventCount: " + str(extra_fields.get("spfEventCount", 0)))
        else:
            fail_reasons.append("No SPF-related events found in Sophos Central alerts")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Publish an SPF TXT record for your sending domain and configure Sophos email security to enforce SPF validation")
        return create_response(
            result=result_dict,
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={"totalAlerts": extra_fields.get("totalAlerts", 0), "spfEventCount": extra_fields.get("spfEventCount", 0)})
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)])
