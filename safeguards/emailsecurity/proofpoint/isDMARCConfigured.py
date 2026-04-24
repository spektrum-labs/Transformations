"""
Transformation: isDMARCConfigured
Vendor: Proofpoint  |  Category: emailsecurity
Evaluates: Inspect the domains response to verify that a DMARC policy is published and
enforced for the organization's primary and active domains (getOrgDomains).
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
                "transformationId": "isDMARCConfigured",
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

        dmarc_configured_count = 0
        dmarc_missing = []
        dmarc_details = []

        for domain in domains:
            if not isinstance(domain, dict):
                continue
            domain_name = domain.get("domain", domain.get("name", "unknown"))
            active = domain.get("active", domain.get("enabled", True))
            if not bool(active):
                continue

            dmarc = domain.get("dmarc", {})
            if not isinstance(dmarc, dict):
                dmarc = {}

            dmarc_record = domain.get("dmarc_record", dmarc.get("record", dmarc.get("value", "")))
            dmarc_enabled = domain.get("dmarc_enabled", dmarc.get("enabled", dmarc.get("configured", None)))
            dmarc_policy = domain.get(
                "dmarc_policy",
                dmarc.get("policy", dmarc.get("p", ""))
            )
            dmarc_status = str(domain.get("dmarc_status", dmarc.get("status", ""))).lower()

            policy_str = str(dmarc_policy).lower()
            has_valid_policy = (
                "reject" in policy_str or
                "quarantine" in policy_str or
                "none" in policy_str
            )
            has_record = bool(dmarc_record)
            is_explicitly_enabled = bool(dmarc_enabled) if dmarc_enabled is not None else False

            is_configured = (has_record and has_valid_policy) or is_explicitly_enabled

            if is_configured:
                dmarc_configured_count = dmarc_configured_count + 1
                dmarc_details.append(domain_name + ": policy=" + policy_str)
            else:
                dmarc_missing.append(domain_name)

        active_domains_checked = dmarc_configured_count + len(dmarc_missing)
        all_configured = (active_domains_checked > 0 and dmarc_configured_count == active_domains_checked)

        return {
            "isDMARCConfigured": all_configured,
            "dmarcConfiguredCount": dmarc_configured_count,
            "totalDomainsChecked": active_domains_checked,
            "domainsMissingDMARC": dmarc_missing
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
                "DMARC is configured on all active domains (" +
                str(extra_fields.get("dmarcConfiguredCount", 0)) + "/" +
                str(extra_fields.get("totalDomainsChecked", 0)) + ")"
            )
        else:
            fail_reasons.append("DMARC is not configured on all active domains")
            missing = extra_fields.get("domainsMissingDMARC", [])
            if missing:
                fail_reasons.append("Domains missing DMARC: " + ", ".join(missing))
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append(
                "Publish a DMARC TXT record (p=quarantine or p=reject) for all active sending domains"
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
