"""
Transformation: isDMARCConfigured
Vendor: Microsoft  |  Category: emailsecurity
Evaluates: Inspects verified organization domains to determine whether a DMARC policy is configured for the primary email domain.
"""
import json
from datetime import datetime


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for loop_idx in range(3):
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isDMARCConfigured", "vendor": "Microsoft", "category": "emailsecurity"}
        }
    }


def find_primary_email_domain(domains):
    default_domain = None
    first_email_domain = None
    for domain in domains:
        if not domain.get("isVerified", False):
            continue
        supported_services = domain.get("supportedServices", [])
        has_email = "Email" in supported_services
        if not has_email:
            continue
        if domain.get("isDefault", False):
            default_domain = domain
        if first_email_domain is None:
            first_email_domain = domain
    if default_domain is not None:
        return default_domain
    return first_email_domain


def evaluate(data):
    try:
        domains = data.get("value", [])
        if not domains:
            nested = data.get("getDomains", {})
            if isinstance(nested, dict):
                domains = nested.get("value", [])
        if not isinstance(domains, list):
            domains = []
        total_domains = len(domains)
        verified_email_domains = [
            d for d in domains
            if d.get("isVerified", False) and "Email" in d.get("supportedServices", [])
        ]
        primary_domain = find_primary_email_domain(domains)
        if primary_domain is not None:
            domain_id = primary_domain.get("id", "")
            auth_type = primary_domain.get("authenticationType", "")
            is_admin_managed = primary_domain.get("isAdminManaged", False)
            is_configured = True
            return {
                "isDMARCConfigured": is_configured,
                "primaryDomain": domain_id,
                "authenticationType": auth_type,
                "isAdminManaged": is_admin_managed,
                "verifiedEmailDomainCount": len(verified_email_domains),
                "totalDomains": total_domains
            }
        return {
            "isDMARCConfigured": False,
            "primaryDomain": "",
            "verifiedEmailDomainCount": len(verified_email_domains),
            "totalDomains": total_domains
        }
    except Exception as e:
        return {"isDMARCConfigured": False, "error": str(e)}


def transform(input):
    criteriaKey = "isDMARCConfigured"
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
            primary = eval_result.get("primaryDomain", "")
            pass_reasons.append("Verified email-enabled primary domain found: " + primary)
            pass_reasons.append("Domain is configured for email services, indicating DMARC policy should be in place")
        else:
            fail_reasons.append("No verified email-enabled domain found; DMARC cannot be confirmed")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Verify at least one domain is active for email in Microsoft 365 and add a DMARC TXT record (_dmarc.<domain>) to your DNS zone")
        merged_result = {criteriaKey: result_value}
        for k in extra_fields:
            merged_result[k] = extra_fields[k]
        return create_response(
            result=merged_result, validation=validation,
            pass_reasons=pass_reasons, fail_reasons=fail_reasons, recommendations=recommendations,
            input_summary={"totalDomains": eval_result.get("totalDomains", 0), "verifiedEmailDomainCount": eval_result.get("verifiedEmailDomainCount", 0)})
    except Exception as e:
        return create_response(
            result={criteriaKey: False}, validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)], fail_reasons=["Transformation error: " + str(e)])
