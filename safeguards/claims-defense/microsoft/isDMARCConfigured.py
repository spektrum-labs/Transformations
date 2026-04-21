"""
Transformation: isDMARCConfigured
Vendor: Microsoft  |  Category: claims-defense
Evaluates: Checks tenant domain configuration records for DMARC TXT entries to confirm DMARC policy is properly set up.
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isDMARCConfigured", "vendor": "Microsoft", "category": "claims-defense"}
        }
    }


def domain_has_dmarc(domain):
    service_config_records = domain.get("serviceConfigurationRecords", [])
    dns_records = domain.get("dnsRecords", service_config_records)
    all_records = service_config_records
    if dns_records and dns_records is not service_config_records:
        all_records = dns_records
    for record in all_records:
        if not isinstance(record, dict):
            continue
        record_type = record.get("recordType", record.get("type", "")).upper()
        label = record.get("label", record.get("name", "")).lower()
        if record_type == "TXT":
            txt_value = record.get("text", record.get("value", "")).lower()
            if "v=dmarc1" in txt_value or "_dmarc" in label:
                return True
    return False


def evaluate(data):
    try:
        domains = data.get("value", [])
        if not isinstance(domains, list):
            domains = []
        total_domains = len(domains)
        dmarc_configured_domains = []
        non_configured_verified_domains = []
        for domain in domains:
            if not isinstance(domain, dict):
                continue
            domain_id = domain.get("id", domain.get("name", "unknown"))
            if domain_has_dmarc(domain):
                dmarc_configured_domains.append(domain_id)
            else:
                is_verified = domain.get("isVerified", False)
                if is_verified:
                    non_configured_verified_domains.append(domain_id)
        dmarc_configured = len(dmarc_configured_domains) > 0
        return {
            "isDMARCConfigured": dmarc_configured,
            "totalDomains": total_domains,
            "dmarcConfiguredDomains": dmarc_configured_domains,
            "nonConfiguredVerifiedDomains": non_configured_verified_domains
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
            pass_reasons.append("DMARC TXT records are configured for at least one verified domain.")
            pass_reasons.append("DMARC-configured domains: " + str(extra_fields.get("dmarcConfiguredDomains", [])))
        else:
            fail_reasons.append("No DMARC TXT records detected in tenant domain configuration.")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Publish a 'v=DMARC1' TXT record at '_dmarc.<yourdomain>' for each verified domain with at least a 'p=quarantine' policy.")
        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={"totalDomains": extra_fields.get("totalDomains", 0)})
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)])
