"""
Transformation: isDKIMConfigured
Vendor: Microsoft  |  Category: digital-operational-resilience-act-dora
Evaluates: Whether DKIM CNAME selector records pointing to Microsoft DKIM signing infrastructure are present for the primary verified domain.
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isDKIMConfigured", "vendor": "Microsoft", "category": "digital-operational-resilience-act-dora"}
        }
    }


def check_dkim_in_domain(domain):
    records = domain.get("serviceConfigurationRecords", [])
    for record in records:
        record_type = record.get("recordType", "")
        label = record.get("label", "") or ""
        canonical = record.get("canonicalName", "") or record.get("text", "") or ""
        if record_type.upper() == "CNAME":
            lower_label = label.lower()
            lower_canonical = canonical.lower()
            if "selector1._domainkey" in lower_label or "selector2._domainkey" in lower_label:
                if "domainkey" in lower_canonical or "mail.protection.outlook.com" in lower_canonical:
                    return True
    return False


def evaluate(data):
    try:
        domains = data.get("value", [])
        if not domains:
            return {"isDKIMConfigured": False, "domainsChecked": 0, "dkimDomains": []}
        dkim_domains = []
        checked = 0
        for domain in domains:
            is_verified = domain.get("isVerified", False)
            if is_verified:
                checked = checked + 1
                domain_id = domain.get("id", "")
                if check_dkim_in_domain(domain):
                    dkim_domains.append(domain_id)
        is_configured = len(dkim_domains) > 0
        return {
            "isDKIMConfigured": is_configured,
            "domainsChecked": checked,
            "dkimDomains": dkim_domains
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
        if result_value:
            pass_reasons.append("DKIM CNAME selector records pointing to Microsoft DKIM infrastructure found for verified domain(s)")
            pass_reasons.append("DKIM configured domains: " + str(extra_fields.get("dkimDomains", [])))
        else:
            fail_reasons.append("No DKIM CNAME selector records found for any verified domain")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Enable DKIM signing in Microsoft 365 Defender or Exchange Online Protection and publish the selector1._domainkey and selector2._domainkey CNAME records for all verified domains")
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
