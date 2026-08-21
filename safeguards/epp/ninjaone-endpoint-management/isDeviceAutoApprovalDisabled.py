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
    data = data if isinstance(data, dict) or isinstance(data, list) else {}

    organizations = []

    if isinstance(data, list):
        organizations = [o for o in data if isinstance(o, dict)]
    elif isinstance(data, dict):
        # Standard case: data is a dict wrapping a list under a key, e.g. "data" or "organizations"
        candidate_list = None
        for key in ["data", "organizations", "items"]:
            val = data.get(key)
            if isinstance(val, list):
                candidate_list = val
                break
        if candidate_list is not None:
            organizations = [o for o in candidate_list if isinstance(o, dict)]
        elif "nodeApprovalMode" in data and isinstance(data.get("nodeApprovalMode"), list):
            # Columnar/parallel-array shape observed in captured tenant response:
            # {"id": [...], "name": [...], "nodeApprovalMode": [...], "nodeCount": [...]}
            ids = data.get("id") or []
            names = data.get("name") or []
            modes = data.get("nodeApprovalMode") or []
            counts = data.get("nodeCount") or []
            n = len(modes)
            for i in range(n):
                org = {
                    "id": ids[i] if i < len(ids) else None,
                    "name": names[i] if i < len(names) else None,
                    "nodeApprovalMode": modes[i],
                    "nodeCount": counts[i] if i < len(counts) else None,
                }
                organizations.append(org)
        elif "nodeApprovalMode" in data:
            # single organization object
            organizations = [data]

    total_orgs = len(organizations)
    auto_approve_orgs = []
    for org in organizations:
        mode = org.get("nodeApprovalMode")
        if isinstance(mode, str) and mode.upper() == "AUTOMATIC":
            auto_approve_orgs.append(org.get("name") or org.get("id") or "unknown")

    input_summary = {
        "totalOrganizations": total_orgs,
        "organizationsWithAutomaticApproval": len(auto_approve_orgs),
    }

    if total_orgs == 0:
        return create_response(
            result={"isDeviceAutoApprovalDisabled": True},
            validation=validation,
            pass_reasons=[],
            fail_reasons=[],
            recommendations=[
                "No organizations were returned by getOrganizations; unable to positively confirm nodeApprovalMode settings. Verify manually in the NinjaOne console."
            ],
            input_summary=input_summary,
            metadata={"transformationId": "isDeviceAutoApprovalDisabled", "vendor": "NinjaOne Endpoint Management", "category": "epp"},
            additional_findings=["No organization records present in getOrganizations response."],
        )

    is_disabled = len(auto_approve_orgs) == 0

    if is_disabled:
        pass_reasons = [
            f"All {total_orgs} organization(s) returned by getOrganizations report nodeApprovalMode other than AUTOMATIC (e.g. manual/none review required)."
        ]
        fail_reasons = []
        recommendations = []
    else:
        pass_reasons = []
        names_str = ", ".join([str(n) for n in auto_approve_orgs])
        fail_reasons = [
            f"{len(auto_approve_orgs)} of {total_orgs} organization(s) have nodeApprovalMode=AUTOMATIC: {names_str}."
        ]
        recommendations = [
            f"Change nodeApprovalMode to MANUAL (or another non-automatic mode) for organization(s): {names_str}, so new devices require technician review before joining the fleet."
        ]

    return create_response(
        result={"isDeviceAutoApprovalDisabled": is_disabled},
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={"transformationId": "isDeviceAutoApprovalDisabled", "vendor": "NinjaOne Endpoint Management", "category": "epp"},
    )
