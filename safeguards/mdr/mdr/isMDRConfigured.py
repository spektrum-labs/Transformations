"""
Transformation: isMDRConfigured
Vendor: MDR (Sophos)  |  Category: MDR
Evaluates: Whether Sophos MDR is fully configured -- authorized contacts list is non-empty
and a threat response mode (Respond, Collaborate, or Notify Only) has been selected.
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isMDRConfigured", "vendor": "MDR", "category": "MDR"}
        }
    }


def evaluate(data):
    try:
        authorized_contacts = data.get("authorizedContacts", [])
        threat_response_mode = data.get("threatResponseMode", "")
        has_authorized_contacts = isinstance(authorized_contacts, list) and len(authorized_contacts) > 0
        has_threat_response_mode = bool(threat_response_mode)
        result = has_authorized_contacts and has_threat_response_mode
        return {
            "isMDRConfigured": result,
            "hasAuthorizedContacts": has_authorized_contacts,
            "authorizedContactsCount": len(authorized_contacts) if isinstance(authorized_contacts, list) else 0,
            "threatResponseMode": threat_response_mode,
            "hasThreatResponseMode": has_threat_response_mode
        }
    except Exception as e:
        return {"isMDRConfigured": False, "error": str(e)}


def transform(input):
    criteriaKey = "isMDRConfigured"
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
        additional_findings = []
        if result_value:
            pass_reasons.append("Sophos MDR is fully configured with authorized contacts and a threat response mode.")
            pass_reasons.append("Authorized contacts count: " + str(extra_fields.get("authorizedContactsCount", 0)))
            pass_reasons.append("Threat response mode: " + str(extra_fields.get("threatResponseMode", "")))
        else:
            if not extra_fields.get("hasAuthorizedContacts", False):
                fail_reasons.append("No authorized contacts have been configured in MDR settings.")
                recommendations.append("Add at least one authorized contact in Sophos Central MDR settings.")
            if not extra_fields.get("hasThreatResponseMode", False):
                fail_reasons.append("No threat response mode is selected in MDR settings.")
                recommendations.append("Select a threat response mode (Respond, Collaborate, or Notify Only) in MDR settings.")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
        additional_findings.append("authorizedContactsCount: " + str(extra_fields.get("authorizedContactsCount", 0)))
        additional_findings.append("threatResponseMode: " + str(extra_fields.get("threatResponseMode", "not set")))
        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={"authorizedContactsCount": extra_fields.get("authorizedContactsCount", 0), "threatResponseMode": extra_fields.get("threatResponseMode", "")},
            additional_findings=additional_findings
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
