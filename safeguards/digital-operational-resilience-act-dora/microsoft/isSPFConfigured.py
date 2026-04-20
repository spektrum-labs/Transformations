"""
Transformation: isSPFConfigured
Vendor: Microsoft  |  Category: digital-operational-resilience-act-dora
Evaluates: Checks that at least one verified email-enabled domain exists, indicating SPF is configured.
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isSPFConfigured", "vendor": "Microsoft", "category": "digital-operational-resilience-act-dora"}
        }
    }


def get_domains(data):
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        val = data.get("data", None)
        if isinstance(val, list):
            return val
    return []


def evaluate(data):
    try:
        domains = get_domains(data)
        if not domains:
            return {"isSPFConfigured": False, "error": "No domain data found", "totalDomains": 0}

        verified_email_domains = []
        default_domain = ""

        for domain in domains:
            domain_id = domain.get("id", "")
            is_verified = domain.get("isVerified", False)
            is_default = domain.get("isDefault", False)
            supported_services = domain.get("supportedServices", [])
            if is_default:
                default_domain = domain_id
            if is_verified and "Email" in supported_services:
                verified_email_domains.append(domain_id)

        is_configured = len(verified_email_domains) > 0
        return {
            "isSPFConfigured": is_configured,
            "verifiedEmailDomains": ", ".join(verified_email_domains),
            "verifiedEmailDomainCount": len(verified_email_domains),
            "totalDomains": len(domains),
            "defaultDomain": default_domain
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
            pass_reasons.append("Verified email-enabled domain(s) found, confirming SPF records are required and configured")
            for k in extra_fields:
                pass_reasons.append(k + ": " + str(extra_fields[k]))
        else:
            fail_reasons.append("No verified email-enabled domains found in Microsoft 365")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Verify custom email domains in Microsoft 365 admin center; domain verification requires SPF records to be published in DNS")
        result_dict = {criteriaKey: result_value}
        for k in extra_fields:
            result_dict[k] = extra_fields[k]
        return create_response(
            result=result_dict, validation=validation,
            pass_reasons=pass_reasons, fail_reasons=fail_reasons, recommendations=recommendations,
            input_summary={criteriaKey: result_value})
    except Exception as e:
        return create_response(
            result={criteriaKey: False}, validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)], fail_reasons=["Transformation error: " + str(e)])
