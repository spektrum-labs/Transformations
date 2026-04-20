"""
Transformation: isSPFConfigured
Vendor: Microsoft  |  Category: control-objectives-for-information-and-related-technologies-cobit
Evaluates: Whether verified email-sending domains exist (proxy for SPF configuration via Graph API domains endpoint).
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isSPFConfigured", "vendor": "Microsoft", "category": "control-objectives-for-information-and-related-technologies-cobit"}
        }
    }


def evaluate(data):
    try:
        domains = data.get("value", [])
        verified_domains = [d for d in domains if d.get("isVerified", False)]
        email_domains = [d for d in verified_domains if "Email" in d.get("supportedServices", [])]
        managed_domains = [d for d in verified_domains if d.get("authenticationType", "") == "Managed"]
        configured = len(email_domains) > 0
        email_ids = [d.get("id", "unknown") for d in email_domains]
        return {
            "isSPFConfigured": configured,
            "totalVerifiedDomains": len(verified_domains),
            "emailCapableDomainCount": len(email_domains),
            "managedDomainCount": len(managed_domains),
            "emailDomainList": email_ids
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
        if result_value:
            pass_reasons.append("Verified email-capable domains exist; SPF is expected to be configured for " + str(extra_fields.get("emailCapableDomainCount", 0)) + " domain(s)")
            domain_list = extra_fields.get("emailDomainList", [])
            if domain_list:
                pass_reasons.append("Email domains: " + ", ".join(domain_list))
        else:
            fail_reasons.append("No verified email-sending domains found; SPF configuration cannot be confirmed")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Add a valid SPF TXT DNS record (v=spf1 include:spf.protection.outlook.com -all) for all verified sending domains in Microsoft 365")
        combined = {criteriaKey: result_value}
        for k in extra_fields:
            combined[k] = extra_fields[k]
        return create_response(
            result=combined, validation=validation,
            pass_reasons=pass_reasons, fail_reasons=fail_reasons, recommendations=recommendations,
            input_summary={criteriaKey: result_value, "emailCapableDomainCount": extra_fields.get("emailCapableDomainCount", 0)},
            additional_findings=["Note: SPF DNS records are not directly exposed via the Microsoft Graph domains API. Evaluation is based on verified email-capable domain presence."])
    except Exception as e:
        return create_response(
            result={criteriaKey: False}, validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)], fail_reasons=["Transformation error: " + str(e)])
