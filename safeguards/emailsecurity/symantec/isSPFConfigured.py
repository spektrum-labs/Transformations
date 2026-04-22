"""
Transformation: isSPFConfigured
Vendor: Symantec  |  Category: emailsecurity
Evaluates: Whether a valid SPF TXT record is published for all domains in Symantec Email Security.cloud.
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isSPFConfigured", "vendor": "Symantec", "category": "emailsecurity"}
        }
    }


def domain_has_spf(domain):
    if not isinstance(domain, dict):
        return False
    spf_keys = ["spf", "spfStatus", "spf_configured", "spfConfigured",
                "spf_status", "spfEnabled", "spf_enabled", "spfRecord", "spf_record"]

    for key in spf_keys:
        if key in domain:
            value = domain[key]
            if isinstance(value, bool):
                return value
            if isinstance(value, str):
                lower_val = value.lower()
                if lower_val in ["true", "yes", "1", "enabled", "configured", "active", "valid", "pass"]:
                    return True
                if lower_val.startswith("v=spf"):
                    return True
            if isinstance(value, dict):
                status = str(value.get("status", "")).lower()
                record = str(value.get("record", "")).lower()
                if status in ["active", "enabled", "configured", "valid", "pass"]:
                    return True
                if record.startswith("v=spf"):
                    return True
    return False


def evaluate(data):
    try:
        domains = data.get("domains", [])
        if not isinstance(domains, list):
            domains = []

        total = len(domains)
        if total == 0:
            return {
                "isSPFConfigured": False,
                "totalDomains": 0,
                "spfConfiguredCount": 0,
                "unconfiguredDomains": []
            }

        configured_count = 0
        unconfigured = []

        for domain in domains:
            if not isinstance(domain, dict):
                continue
            if domain_has_spf(domain):
                configured_count = configured_count + 1
            else:
                domain_name = domain.get("name", domain.get("domain", domain.get("domainName", "unknown")))
                unconfigured.append(str(domain_name))

        all_configured = configured_count == total

        return {
            "isSPFConfigured": all_configured,
            "totalDomains": total,
            "spfConfiguredCount": configured_count,
            "unconfiguredDomains": unconfigured
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
        additional_findings = []
        total = extra_fields.get("totalDomains", 0)
        configured = extra_fields.get("spfConfiguredCount", 0)
        unconfigured = extra_fields.get("unconfiguredDomains", [])
        if result_value:
            pass_reasons.append("SPF records are configured on all " + str(total) + " domain(s).")
        else:
            fail_reasons.append("SPF is not configured on all domains. " + str(configured) + " of " + str(total) + " domains configured.")
            if unconfigured:
                recommendations.append("Publish a valid SPF TXT record in DNS for: " + ", ".join(unconfigured))
                additional_findings.append("Domains missing SPF: " + ", ".join(unconfigured))
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={"totalDomains": total})
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)])
