"""
Transformation: isDKIMConfigured
Vendor: Sophos  |  Category: control-objectives-for-information-and-related-technologies-cobit
Evaluates: Check for evidence of DKIM email authentication configuration by scanning
Sophos Central alerts for email security events related to DKIM signing configuration.
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isDKIMConfigured", "vendor": "Sophos", "category": "control-objectives-for-information-and-related-technologies-cobit"}
        }
    }


def evaluate(data):
    try:
        items = data.get("items", [])
        total_alerts = len(items)
        dkim_events = []
        for alert in items:
            description = alert.get("description", "").lower()
            alert_type = alert.get("type", "").lower()
            category = alert.get("category", "").lower()
            product = alert.get("product", "").lower()
            if "dkim" in description or "dkim" in alert_type or "dkim" in category or "dkim" in product:
                dkim_events.append(alert.get("id", "unknown"))
        is_configured = len(dkim_events) > 0
        return {
            "isDKIMConfigured": is_configured,
            "totalAlerts": total_alerts,
            "dkimEventCount": len(dkim_events),
            "dkimEventIds": dkim_events[:10],
            "note": "DKIM configuration is a DNS-level control; Sophos alerts provide indirect evidence only"
        }
    except Exception as e:
        return {"isDKIMConfigured": False, "error": str(e)}


def transform(input):
    criteriaKey = "isDKIMConfigured"
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
            pass_reasons.append("DKIM-related email security events found in Sophos Central alerts")
            pass_reasons.append("dkimEventCount: " + str(extra_fields.get("dkimEventCount", 0)))
        else:
            fail_reasons.append("No DKIM-related events found in Sophos Central alerts")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Configure DKIM signing for your email domain and verify via DNS; Sophos does not natively manage DKIM but email security alerts can confirm its status")
        return create_response(
            result=result_dict,
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={"totalAlerts": extra_fields.get("totalAlerts", 0), "dkimEventCount": extra_fields.get("dkimEventCount", 0)})
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)])
