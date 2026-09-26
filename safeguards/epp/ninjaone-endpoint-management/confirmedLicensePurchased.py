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
        organizations = data
    elif isinstance(data, dict):
        organizations = data.get("data") or data.get("results") or []
        if not organizations and "id" in data:
            organizations = [data]
    else:
        organizations = []

    total_orgs = len(organizations)
    active_orgs = []
    for org in organizations:
        if not isinstance(org, dict):
            continue
        org_id = org.get("id")
        org_name = org.get("name")
        approval_mode = org.get("nodeApprovalMode")
        if org_id is not None and org_name:
            active_orgs.append(org)

    is_licensed = total_orgs > 0 and len(active_orgs) > 0

    org_names = [o.get("name") for o in active_orgs]

    if is_licensed:
        pass_reasons = [
            f"NinjaOne tenant returned {total_orgs} active organization(s) via /v2/organizations "
            f"({', '.join([str(n) for n in org_names])}), confirming the endpoint management "
            f"license/subscription is active and the tenant is provisioned."
        ]
        fail_reasons = []
        recommendations = []
    else:
        pass_reasons = []
        fail_reasons = [
            f"No valid organizations were returned by /v2/organizations (total_orgs={total_orgs}); "
            "this indicates the tenant has no confirmed active endpoint management license or the "
            "credentials do not have access to any organization."
        ]
        recommendations = [
            "Verify the NinjaOne tenant has an active endpoint management subscription and that the "
            "OAuth client credentials are scoped to at least one organization."
        ]

    result = {
        "confirmedLicensePurchased": is_licensed,
        "totalOrganizations": total_orgs,
        "activeOrganizationNames": org_names,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={"totalOrganizations": total_orgs},
        metadata={
            "transformationId": "confirmedLicensePurchased",
            "vendor": "NinjaOne",
            "category": "epp",
        },
    )
