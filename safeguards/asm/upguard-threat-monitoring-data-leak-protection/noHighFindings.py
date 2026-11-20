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
        if not isinstance(risks, list):
            risks = []
    else:
        risks = []

    high_risks = []
    for r in risks:
        if not isinstance(r, dict):
            continue
        severity = (r.get("severity") or "").lower()
        if severity == "high":
            waivers = r.get("risk_waivers") or []
            waived = False
            if isinstance(waivers, list) and len(waivers) > 0:
                waived = True
            if not waived:
                high_risks.append(r)

    total_risks = len(risks)
    high_count = len(high_risks)
    no_high_findings = high_count == 0

    findings_sample = [
        {
            "id": r.get("id"),
            "finding": r.get("finding"),
            "hostnames": r.get("hostnames") or [],
        }
        for r in high_risks[:10]
    ]

    if no_high_findings:
        pass_reasons = [
            f"Scanned {total_risks} risk records from the /risks feed; none carry severity='high' (unwaived)."
        ]
        fail_reasons = []
        recommendations = []
    else:
        pass_reasons = []
        sample_ids = ", ".join([str(r.get("id")) for r in high_risks[:5]])
        fail_reasons = [
            f"Found {high_count} open high-severity risk(s) out of {total_risks} total risk records "
            f"(e.g. {sample_ids})."
        ]
        recommendations = [
            f"Remediate or waive the {high_count} open high-severity finding(s): {sample_ids}."
        ]

    result = {
        "noHighFindings": no_high_findings,
        "highSeverityOpenCount": high_count,
        "totalRisksEvaluated": total_risks,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={
            "totalRisksEvaluated": total_risks,
            "highSeverityOpenCount": high_count,
            "highSeveritySample": findings_sample,
        },
        metadata={
            "transformationId": "noHighFindings",
            "vendor": "UpGuard Threat Monitoring Data Leak Protection",
            "category": "asm",
        },
    )
