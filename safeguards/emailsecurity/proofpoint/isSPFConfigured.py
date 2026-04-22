"""
Transformation: isSPFConfigured
Vendor: Proofpoint  |  Category: emailsecurity
Evaluates: Inspect the domains response to verify that a valid SPF record is published
for the organization's active domains (getOrgDomains).
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
            "dataCollection": {
                "status": "error" if (api_errors or []) else "success",
                "errors": api_errors or []
            },
            "validation": {
                "status": validation.get("status", "unknown"),
                "errors": validation.get("errors", []),
                "warnings": validation.get("warnings", [])
            },
            "transformation": {
                "status": "error" if (transformation_errors or []) else "success",
                "errors": transformation_errors or [],
                "inputSummary": input_summary or {}
            },
            "evaluation": {
                "passReasons": pass_reasons or [],
                "failReasons": fail_reasons or [],
                "recommendations": recommendations or [],
                "additionalFindings": additional_findings or []
            },
            "metadata": {
                "evaluatedAt": datetime.utcnow().isoformat() + "Z",
                "schemaVersion": "1.0",
                "transformationId": "isSPFConfigured",
                "vendor": "Proofpoint",
                "category": "emailsecurity"
            }
        }
    }


def evaluate(data):
    try:
        domains = []
        if isinstance(data, list):
            domains = data
        elif isinstance(data, dict):
            domains = data.get("domains", [])
            if not isinstance(domains, list):
                domains = []

        spf_configured_count = 0
        spf_missing = []

        for domain in domains:
            if not isinstance(domain, dict):
                continue
            domain_name = domain.get("domain", domain.get("name", "unknown"))
            active = domain.get("active", domain.get("enabled", True))
            if not bool(active):
                continue

            spf = domain.get("spf", {})
            if not isinstance(spf, dict):
                spf = {}

            spf_enabled = domain.get("spf_enabled", spf.get("enabled", spf.get("configured", None)))
            spf_record = domain.get("spf_record", spf.get("record", spf.get("value", "")))
            spf_status = str(domain.get("spf_status", spf.get("status", ""))).lower()

            record_str = str(spf_record).lower()
            has_valid_record = "v=spf1" in record_str
            is_explicitly_enabled = bool(spf_enabled) if spf_enabled is not None else False
            has_valid_status = (
                "valid" in spf_status or
                "active" in spf_status or
                "verified" in spf_status or
                "pass" in spf_status
            )

            is_configured = is_explicitly_enabled or has_valid_record or has_valid_status

            if is_configured:
                spf_configured_count = spf_configured_count + 1
            else:
                spf_missing.append(domain_name)

        active_domains_checked = spf_configured_count + len(spf_missing)
        all_configured = (active_domains_checked > 0 and spf_configured_count == active_domains_checked)

        return {
            "isSPFConfigured": all_configured,
            "spfConfiguredCount": spf_configured_count,
            "totalDomainsChecked": active_domains_checked,
            "domainsMissingSPF": spf_missing
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
            return create_response(
                result={criteriaKey: False},
                validation=validation,
                fail_reasons=["Input validation failed"]
            )
        eval_result = evaluate(data)
        result_value = eval_result.get(criteriaKey, False)
        extra_fields = {}
        for k in eval_result:
            if k != criteriaKey and k != "error":
                extra_fields[k] = eval_result[k]
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        if result_value:
            pass_reasons.append(
                "SPF is configured on all active domains (" +
                str(extra_fields.get("spfConfiguredCount", 0)) + "/" +
                str(extra_fields.get("totalDomainsChecked", 0)) + ")"
            )
        else:
            fail_reasons.append("SPF is not configured on all active domains")
            missing = extra_fields.get("domainsMissingSPF", [])
            if missing:
                fail_reasons.append("Domains missing SPF: " + ", ".join(missing))
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append(
                "Publish a valid SPF TXT record (v=spf1 ... -all) for all active sending domains"
            )
        result_dict = {criteriaKey: result_value}
        for k in extra_fields:
            result_dict[k] = extra_fields[k]
        input_summary = {criteriaKey: result_value}
        for k in extra_fields:
            input_summary[k] = extra_fields[k]
        return create_response(
            result=result_dict,
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary=input_summary
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
