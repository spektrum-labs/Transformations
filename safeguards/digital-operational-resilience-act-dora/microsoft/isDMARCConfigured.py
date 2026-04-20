"""
Transformation: isDMARCConfigured
Vendor: Microsoft  |  Category: digital-operational-resilience-act-dora
Evaluates: Whether a DMARC TXT record (v=DMARC1) is present in the primary verified domain's service configuration records.
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isDMARCConfigured", "vendor": "Microsoft", "category": "digital-operational-resilience-act-dora"}
        }
    }


def check_dmarc_in_domain(domain):
    records = domain.get("serviceConfigurationRecords", [])
    for record in records:
        record_type = record.get("recordType", "")
        txt_value = record.get("text", "") or record.get("label", "")
        if record_type.upper() == "TXT":
            if "v=dmarc1" in txt_value.lower():
                return True
    return False


def evaluate(data):
    try:
        domains = data.get("value", [])
        if not domains:
            return {"isDMARCConfigured": False, "domainsChecked": 0, "dmarcDomains": []}
        dmarc_domains = []
        checked = 0
        for domain in domains:
            is_verified = domain.get("isVerified", False)
            if is_verified:
                checked = checked + 1
                domain_id = domain.get("id", "")
                if check_dmarc_in_domain(domain):
                    dmarc_domains.append(domain_id)
        is_configured = len(dmarc_domains) > 0
        return {
            "isDMARCConfigured": is_configured,
            "domainsChecked": checked,
            "dmarcDomains": dmarc_domains
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
            pass_reasons.append("DMARC TXT record (v=DMARC1) found for verified domain(s)")
            pass_reasons.append("DMARC configured domains: " + str(extra_fields.get("dmarcDomains", [])))
        else:
            fail_reasons.append("No DMARC TXT record found for any verified domain")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Publish a DMARC TXT record (v=DMARC1; p=quarantine or p=reject) for all verified domains to protect against email spoofing")
        result_dict = {criteriaKey: result_value}
        for k in extra_fields:
            result_dict[k] = extra_fields[k]
        summary_dict = {criteriaKey: result_value}
        for k in extra_fields:
            summary_dict[k] = extra_fields[k]
        return create_response(
            result=result_dict, validation=validation,
            pass_reasons=pass_reasons, fail_reasons=fail_reasons, recommendations=recommendations,
            input_summary=summary_dict)
    except Exception as e:
        return create_response(
            result={criteriaKey: False}, validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)], fail_reasons=["Transformation error: " + str(e)])
