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
    roles = data.get("data") or []
    if not isinstance(roles, list):
        roles = []

    total_roles = len(roles)

    scoped_roles = []
    cse_scoped_roles = []
    blanket_admin_roles = []

    for r in roles:
        if not isinstance(r, dict):
            continue
        caps = r.get("capabilities")
        name = r.get("name") or "unknown"
        filter_pred = r.get("filterPredicate")
        if isinstance(caps, list) and len(caps) > 0:
            scoped_roles.append(name)
            has_cse_cap = False
            for c in caps:
                if isinstance(c, str) and ("cse" in c.lower()):
                    has_cse_cap = True
                    break
            if has_cse_cap:
                cse_scoped_roles.append(name)
        else:
            if filter_pred == "*":
                blanket_admin_roles.append(name)

    custom_role_count = len(scoped_roles)
    cse_scoped_count = len(cse_scoped_roles)

    is_rbac_enabled = total_roles > 1 and custom_role_count > 0

    input_summary = {
        "totalRoles": total_roles,
        "scopedRoleCount": custom_role_count,
        "cseScopedRoleCount": cse_scoped_count,
        "blanketAdminRoleCount": len(blanket_admin_roles),
    }

    if is_rbac_enabled:
        sample_scoped = scoped_roles[:5]
        pass_reasons = [
            (
                f"Found {custom_role_count} of {total_roles} roles with explicit scoped "
                f"capabilities arrays (e.g. {', '.join(sample_scoped)}), distinct from "
                "blanket administrator access."
            )
        ]
        if cse_scoped_count > 0:
            pass_reasons.append(
                f"{cse_scoped_count} role(s) ({', '.join(cse_scoped_roles[:5])}) carry "
                "Cloud SIEM-specific capabilities (capability names containing 'cse', e.g. "
                "cseViewAutomations, cseViewEntity, cseCommentOnInsights), evidencing "
                "scoped Insights/Content/Configuration access rather than blanket admin."
            )
        fail_reasons = []
        recommendations = []
    else:
        pass_reasons = []
        fail_reasons = [
            (
                f"Only {total_roles} role(s) were returned and {custom_role_count} of them "
                "define a scoped capabilities array; the tenant appears to rely on blanket "
                "administrator-style roles (filterPredicate='*' with no capability scoping)."
            )
        ]
        recommendations = [
            "Create Cloud SIEM roles scoped to specific capability sets (Insights, "
            "Content, Configuration) instead of granting broad Administrator access to all users."
        ]

    result = {
        "isRBACEnabled": is_rbac_enabled,
        "totalRoles": total_roles,
        "scopedRoleCount": custom_role_count,
        "cseScopedRoleCount": cse_scoped_count,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "isRBACEnabled",
            "vendor": "Sumo Logic Continuous Intelligence Service",
            "category": "incidentmgmt",
        },
    )
