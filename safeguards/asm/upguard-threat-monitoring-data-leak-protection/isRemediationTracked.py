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


def transform(input):
    data, validation = extract_input(input)
    data = data if isinstance(data, (dict, list)) else {}

    if isinstance(data, list):
        risks = data
    elif isinstance(data, dict):
        risks = data.get("risks") or data.get("data") or []
    else:
        risks = []

    total_risks = len(risks)
    with_remediation = 0
    with_waivers = 0
    sample_findings = []

    for r in risks:
        if not isinstance(r, dict):
            continue
        remediation = r.get("remediation")
        if isinstance(remediation, str) and remediation.strip():
            with_remediation = with_remediation + 1
        waivers = r.get("risk_waivers")
        if isinstance(waivers, list):
            with_waivers = with_waivers + 1
        elif waivers:
            with_waivers = with_waivers + 1
        if len(sample_findings) < 3 and r.get("finding"):
            sample_findings.append(r.get("finding"))

    tracking_evidence = with_remediation > 0 or with_waivers > 0
    is_tracked = bool(tracking_evidence and total_risks > 0)

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if is_tracked:
        pass_reasons.append(
            f"Of {total_risks} risk findings returned by /risks, {with_remediation} carry a populated "
            f"'remediation' field and {with_waivers} carry a 'risk_waivers' attribute, showing the platform "
            f"tracks remediation guidance and waiver/acceptance state per finding (e.g. findings: {sample_findings})."
        )
    else:
        fail_reasons.append(
            f"None of the {total_risks} risk findings returned by /risks carried a populated 'remediation' "
            f"field or a 'risk_waivers' attribute, so no remediation-tracking state could be confirmed."
        )
        recommendations.append(
            "Verify the UpGuard account has risk remediation workflows configured (waivers/requests) so that "
            "the /risks feed populates remediation and risk_waivers fields for findings."
        )

    input_summary = {
        "totalRisks": total_risks,
        "risksWithRemediationField": with_remediation,
        "risksWithWaiversField": with_waivers,
    }

    return create_response(
        result={
            "isRemediationTracked": is_tracked,
            "totalRisks": total_risks,
            "risksWithRemediationField": with_remediation,
            "risksWithWaiversField": with_waivers,
        },
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "isRemediationTracked",
            "vendor": "UpGuard Threat Monitoring Data Leak Protection",
            "category": "asm",
        },
    )
