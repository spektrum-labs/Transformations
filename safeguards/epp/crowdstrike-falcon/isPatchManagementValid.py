import json
from datetime import datetime


def extract_input(input_data):
    """Extract data and validation from input, handling enriched + legacy formats."""
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for _ in range(3):
            unwrapped = False
            for key in wrapper_keys:
                if key in data and isinstance(data.get(key), dict):
                    data = data[key]
                    unwrapped = True
                    break
            if not unwrapped:
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
    """Create the standardized 5-section transformation response."""
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
    data = data if isinstance(data, dict) else {}

    api_errors = []
    if data.get("error") is True or data.get("statusCode") == 500:
        api_errors.append(
            "Vendor API returned an error response: %s" % str(data.get("message") or data.get("errorMessage") or "unknown error")
        )

    resources = data.get("resources") or []
    if not isinstance(resources, list):
        resources = []

    total = len(resources)
    remediated_count = 0
    open_without_remediation = 0

    for item in resources:
        if not isinstance(item, dict):
            continue
        status = item.get("status") or ""
        remediation = item.get("remediation") or {}
        remediation_ids = remediation.get("ids") if isinstance(remediation, dict) else None
        has_remediation = bool(remediation_ids)
        if has_remediation:
            remediated_count = remediated_count + 1
        if status.upper() == "OPEN" and not has_remediation:
            open_without_remediation = open_without_remediation + 1

    if total == 0:
        is_valid = False
        pass_reasons = []
        fail_reasons = [
            "No Spotlight vulnerability/remediation records were returned for this tenant, so patch remediation tracking could not be confirmed active."
        ]
        recommendations = [
            "Verify Falcon Spotlight module is enabled and returning vulnerability data, and confirm the Sensor Update Policy build tag configuration separately."
        ]
        if api_errors:
            fail_reasons.append(
                "Underlying API call failed: %s" % api_errors[0]
            )
            recommendations.append(
                "Investigate the Spotlight vulnerabilities API connectivity/error before re-evaluating patch management validity."
            )
    else:
        remediation_rate = (remediated_count * 100.0) / total
        is_valid = remediation_rate >= 50.0
        if is_valid:
            pass_reasons = [
                f"{remediated_count} of {total} tracked vulnerabilities ({remediation_rate:.1f}%) have remediation.ids populated, indicating patch remediation tracking is active and effective across the host group."
            ]
            fail_reasons = []
            recommendations = []
        else:
            pass_reasons = []
            fail_reasons = [
                f"Only {remediated_count} of {total} tracked vulnerabilities ({remediation_rate:.1f}%) have remediation.ids populated; {open_without_remediation} are OPEN with no remediation tracking, indicating the Sensor Update Policy build tag is not being consistently enforced against deployed agent_version."
            ]
            recommendations = [
                "Review the Sensor Update Policy build tag (e.g. N-1/N-2) assignment for affected host groups and confirm agent_version reports match the configured tag.",
                "Ensure OPEN vulnerabilities are linked to an active remediation/patch record."
            ]

    result = {
        "isPatchManagementValid": is_valid,
        "totalVulnerabilities": total,
        "remediatedCount": remediated_count,
        "openWithoutRemediationCount": open_without_remediation,
    }

    input_summary = {
        "totalVulnerabilities": total,
        "remediatedCount": remediated_count,
        "openWithoutRemediationCount": open_without_remediation,
    }

    metadata = {
        "transformationId": "isPatchManagementValid",
        "vendor": "CrowdStrike Falcon",
        "category": "epp",
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata=metadata,
        api_errors=api_errors,
    )
