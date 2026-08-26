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
    data = data if isinstance(data, (dict, list)) else {}

    if isinstance(data, list):
        orgs = data
    elif isinstance(data, dict):
        orgs = data.get("data") or data.get("results") or data.get("organizations") or []
        if not isinstance(orgs, list):
            orgs = []
    else:
        orgs = []

    total_orgs = len(orgs)
    automatic_orgs = []
    non_automatic_orgs = []

    for org in orgs:
        if not isinstance(org, dict):
            continue
        mode = org.get("nodeApprovalMode")
        name = org.get("name") or ("org id %s" % org.get("id"))
        if mode == "AUTOMATIC":
            automatic_orgs.append(name)
        else:
            non_automatic_orgs.append((name, mode))

    is_disabled = total_orgs > 0 and len(automatic_orgs) == 0

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if total_orgs == 0:
        fail_reasons.append("No organization records were returned by getOrganizations, so nodeApprovalMode could not be verified for any organization.")
        recommendations.append("Verify API connectivity and confirm the getOrganizations endpoint returns organization records.")
    elif is_disabled:
        modes_summary = ", ".join(["%s=%s" % (n, m) for n, m in non_automatic_orgs]) if non_automatic_orgs else "no organizations configured"
        pass_reasons.append(
            "All %d organization(s) have nodeApprovalMode other than AUTOMATIC (%s), meaning new devices require manual technician approval before joining the fleet." % (total_orgs, modes_summary)
        )
    else:
        fail_reasons.append(
            "%d of %d organization(s) have nodeApprovalMode=AUTOMATIC (%s), meaning new devices are auto-approved onto the fleet without technician review." % (
                len(automatic_orgs), total_orgs, ", ".join(automatic_orgs)
            )
        )
        recommendations.append(
            "Change nodeApprovalMode to MANUAL (or REJECT) for the following organization(s) so new devices require technician review before joining the fleet: %s." % ", ".join(automatic_orgs)
        )

    result = {
        "isDeviceAutoApprovalDisabled": is_disabled,
        "totalOrganizations": total_orgs,
        "automaticApprovalOrganizations": automatic_orgs,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={"totalOrganizations": total_orgs, "automaticCount": len(automatic_orgs)},
        metadata={
            "transformationId": "isDeviceAutoApprovalDisabled",
            "vendor": "NinjaOne Endpoint Management",
            "category": "epp",
        },
    )
