import json
from datetime import datetime


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for _ in range(3):
            unwrapped = False
            for key in wrapper_keys:
                if key in data and isinstance(data.get(key), (dict, list)):
                    data = data[key]
                    unwrapped = True
                    break
            if not unwrapped or not isinstance(data, dict):
                break
    validation = {
        "status": "unknown",
        "errors": [],
        "warnings": ["Legacy input format - no schema validation performed"],
    }
    return data, validation


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, metadata=None,
                    transformation_errors=None, api_errors=None, additional_findings=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    api_err_list = api_errors or []
    transform_err_list = transformation_errors or []
    data_collection_status = "error" if api_err_list else "success"
    transformation_status = "error" if transform_err_list else "success"
    response_metadata = {
        "evaluatedAt": datetime.utcnow().isoformat() + "Z",
        "schemaVersion": "2.0",
    }
    if metadata:
        response_metadata.update(metadata)
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": data_collection_status, "errors": api_err_list},
            "validation": {
                "status": validation.get("status", "unknown"),
                "errors": validation.get("errors", []),
                "warnings": validation.get("warnings", []),
            },
            "transformation": {
                "status": transformation_status,
                "errors": transform_err_list,
                "inputSummary": input_summary or {},
            },
            "evaluation": {
                "passReasons": pass_reasons or [],
                "failReasons": fail_reasons or [],
                "recommendations": recommendations or [],
                "additionalFindings": additional_findings or [],
            },
            "metadata": response_metadata,
        },
    }


TAKEOVER_KEYWORDS = [
    "takeover",
    "dangling",
    "dangling dns",
    "vulnerable to takeover",
    "potentially vulnerable to takeover",
]


def transform(input):
    data, validation = extract_input(input)
    data = data if isinstance(data, (dict, list)) else {}

    if isinstance(data, list):
        risks = data
    elif isinstance(data, dict):
        risks = data.get("risks") or data.get("data") or []
    else:
        risks = []

    if not isinstance(risks, list):
        risks = []

    takeover_risks = []
    dns_category_count = 0

    for r in risks:
        if not isinstance(r, dict):
            continue
        category = (r.get("category") or "").lower()
        risk_type = (r.get("riskType") or "").lower()
        risk_subtype = (r.get("riskSubtype") or "").lower()
        finding = (r.get("finding") or "").lower()
        risk_text = (r.get("risk") or "").lower()
        rid = (r.get("id") or "").lower()

        if category == "dns":
            dns_category_count = dns_category_count + 1

        haystack = " ".join([finding, risk_text, rid, risk_type, risk_subtype])
        matched = False
        for kw in TAKEOVER_KEYWORDS:
            if kw in haystack:
                matched = True
                break
        if matched:
            takeover_risks.append(r)

    detected = len(takeover_risks) > 0

    total_risks = len(risks)

    input_summary = {
        "totalRisks": total_risks,
        "dnsCategoryRisks": dns_category_count,
        "takeoverMatchedRisks": len(takeover_risks),
    }

    if detected:
        sample = takeover_risks[0]
        hostnames = sample.get("hostnames") or []
        pass_reasons = [
            f"Found {len(takeover_risks)} risk record(s) matching subdomain takeover / dangling DNS indicators out of {total_risks} total risks scanned. "
            f"Example: id='{sample.get('id')}', finding='{sample.get('finding')}', affecting hostnames={hostnames}."
        ]
        fail_reasons = []
        recommendations = []
    else:
        pass_reasons = []
        fail_reasons = [
            f"None of the {total_risks} risk records returned by /risks matched subdomain takeover or dangling DNS keywords "
            f"(checked finding/risk/id/riskType/riskSubtype text against terms: {', '.join(TAKEOVER_KEYWORDS)}). "
            f"{dns_category_count} risk(s) were in the 'dns' category but did not indicate takeover."
        ]
        recommendations = [
            "Confirm UpGuard's Domains/Risk Profile view for this account for any 'Vulnerable to takeover', "
            "'Potentially vulnerable to takeover', or 'Dangling DNS' findings not present in this /risks page, "
            "and ensure DNS records pointing to deprovisioned cloud resources (e.g. stale CNAMEs) are removed."
        ]

    result = {
        "isSubdomainTakeoverDetected": detected,
        "takeoverRiskCount": len(takeover_risks),
        "totalRisksScanned": total_risks,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "isSubdomainTakeoverDetected",
            "vendor": "UpGuard Threat Monitoring Data Leak Protection",
            "category": "asm",
        },
    )
