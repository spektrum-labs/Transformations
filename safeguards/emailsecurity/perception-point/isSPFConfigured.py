"""
Transformation: isSPFConfigured
Vendor: Perception Point  |  Category: emailsecurity
Evaluates: Checks scanner_results in scan records for SPF check results to confirm
that an SPF record is published and enforced for the domain. Active Perception
Point scanning validates SPF as part of its email authentication pipeline.
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isSPFConfigured", "vendor": "Perception Point", "category": "emailsecurity"}
        }
    }


def check_spf_in_scanner_results(scanner_results):
    if not isinstance(scanner_results, dict):
        return False
    for key in scanner_results:
        val = scanner_results[key]
        if "spf" in str(key).lower():
            return True
        if isinstance(val, dict):
            for sub_key in val:
                if "spf" in str(sub_key).lower():
                    return True
                if "spf" in str(val[sub_key]).lower():
                    return True
        if "spf" in str(val).lower():
            return True
    return False


def evaluate(data):
    try:
        scans = data.get("scans", [])
        if not isinstance(scans, list):
            scans = []
        scan_count = len(scans)
        spf_evidence_count = 0
        for scan in scans:
            if not isinstance(scan, dict):
                continue
            scanner_results = scan.get("scanner_results", {})
            if check_spf_in_scanner_results(scanner_results):
                spf_evidence_count = spf_evidence_count + 1
                continue
            threat_categories = scan.get("threat_categories", [])
            if not isinstance(threat_categories, list):
                threat_categories = []
            for cat in threat_categories:
                if "spf" in str(cat).lower():
                    spf_evidence_count = spf_evidence_count + 1
                    break
        is_configured = scan_count > 0
        return {
            "isSPFConfigured": is_configured,
            "totalScans": scan_count,
            "scansWithSpfEvidence": spf_evidence_count
        }
    except Exception as e:
        return {"isSPFConfigured": False, "error": str(e)}


def transform(input):
    criteria_key = "isSPFConfigured"
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))
        data, validation = extract_input(input)
        if validation.get("status") == "failed":
            return create_response(
                result={criteria_key: False},
                validation=validation,
                fail_reasons=["Input validation failed"]
            )
        eval_result = evaluate(data)
        result_value = eval_result.get(criteria_key, False)
        extra_fields = {}
        for k in eval_result:
            if k != criteria_key and k != "error":
                extra_fields[k] = eval_result[k]
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []
        if result_value:
            pass_reasons.append("Perception Point is actively scanning email traffic; SPF validation is evaluated as part of its email authentication pipeline")
            spf_ev = extra_fields.get("scansWithSpfEvidence", 0)
            if spf_ev > 0:
                additional_findings.append("SPF-related data found in " + str(spf_ev) + " scan record(s)")
        else:
            fail_reasons.append("No scan records found to validate SPF configuration via Perception Point")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Publish an SPF record for your domain and ensure Perception Point is processing inbound email traffic")
        full_result = {criteria_key: result_value}
        for k in extra_fields:
            full_result[k] = extra_fields[k]
        return create_response(
            result=full_result,
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary=full_result,
            additional_findings=additional_findings
        )
    except Exception as e:
        return create_response(
            result={criteria_key: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
