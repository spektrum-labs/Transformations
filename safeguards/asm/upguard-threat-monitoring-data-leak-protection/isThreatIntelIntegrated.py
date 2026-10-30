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


THREAT_INTEL_CATEGORY_MARKERS = [
    "breach",
    "leak",
    "dark_web",
    "darkweb",
    "identity_breach",
    "credential_leak",
    "leaked_credential",
    "exposed_credential",
    "third_party_breach",
    "data_leak",
    "compromised_credential",
]


def transform(input):
    data, validation = extract_input(input)
    data = data if isinstance(data, (dict, list)) else {}

    if isinstance(data, list):
        risks = data
    elif isinstance(data, dict):
        risks = data.get("risks") or data.get("data") or []
        if not isinstance(risks, list):
            risks = []
    else:
        risks = []

    total_risks = len(risks)
    matched = []
    categories_seen = []

    for r in risks:
        if not isinstance(r, dict):
            continue
        category = str(r.get("category") or "").lower()
        risk_type = str(r.get("riskType") or "").lower()
        risk_subtype = str(r.get("riskSubtype") or "").lower()

        if category and category not in categories_seen:
            categories_seen.append(category)

        combined = category + " " + risk_type + " " + risk_subtype

        for marker in THREAT_INTEL_CATEGORY_MARKERS:
            if marker in combined:
                matched.append({
                    "id": r.get("id"),
                    "finding": r.get("finding"),
                    "category": r.get("category"),
                    "riskType": r.get("riskType"),
                    "matchedOn": marker,
                })
                break

    is_integrated = len(matched) > 0

    input_summary = {
        "totalRisksEvaluated": total_risks,
        "threatIntelMatchedCount": len(matched),
        "categoriesObserved": categories_seen,
    }

    if is_integrated:
        sample_findings = "; ".join([
            f"{m.get('finding')} (category={m.get('category')}, riskType={m.get('riskType')}, matched='{m.get('matchedOn')}')"
            for m in matched[:5]
        ])
        pass_reasons = [
            f"Found {len(matched)} of {total_risks} risk findings in the /risks feed carrying a "
            f"category/riskType/riskSubtype classified as breach, leak, dark-web, or leaked-credential "
            f"related. Examples: {sample_findings}"
        ]
        fail_reasons = []
        recommendations = []
    else:
        pass_reasons = []
        fail_reasons = [
            f"None of the {total_risks} risk findings retrieved from the /risks feed carried a category, "
            f"riskType, or riskSubtype classified as breach/leak/dark-web/leaked-credential related. "
            f"Observed categories for this tenant were: {', '.join(categories_seen) if categories_seen else 'none'}. "
            f"The findings surfaced are technical configuration/vulnerability scan results "
            f"(e.g. SSL, DNS, email security, HTTP headers), not externally sourced threat intelligence."
        ]
        recommendations = [
            "Enable UpGuard's Identity Breach / dark-web and leaked-credential monitoring modules for this "
            "tenant so that externally sourced breach and credential-exposure findings are surfaced in the "
            "risks feed alongside technical scan findings."
        ]

    result = {
        "isThreatIntelIntegrated": is_integrated,
        "totalRisksEvaluated": total_risks,
        "threatIntelMatchedCount": len(matched),
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "isThreatIntelIntegrated",
            "vendor": "UpGuard Threat Monitoring Data Leak Protection",
            "category": "asm",
        },
    )
