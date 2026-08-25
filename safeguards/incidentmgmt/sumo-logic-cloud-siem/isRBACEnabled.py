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

    role_count = len(roles)
    role_names = [r.get("name") for r in roles if isinstance(r, dict) and r.get("name")]

    cap_counts = []
    for r in roles:
        if isinstance(r, dict):
            caps = r.get("capabilities") or []
            if isinstance(caps, list):
                cap_counts.append(len(caps))
            else:
                cap_counts.append(0)
        else:
            cap_counts.append(0)

    max_cap = max(cap_counts) if cap_counts else 0

    scoped_roles = []
    for r in roles:
        if not isinstance(r, dict):
            continue
        caps = r.get("capabilities") or []
        cap_len = len(caps) if isinstance(caps, list) else 0
        if cap_len > 0 and cap_len < max_cap:
            scoped_roles.append(r.get("name"))

    is_rbac_enabled = role_count > 1 and len(scoped_roles) > 0

    input_summary = {
        "totalRoles": role_count,
        "roleNames": role_names,
        "maxCapabilityCount": max_cap,
        "scopedRoleNames": scoped_roles,
    }

    if is_rbac_enabled:
        pass_reasons = [
            f"Tenant has {role_count} configured roles ({', '.join([str(n) for n in role_names])}), "
            f"of which {len(scoped_roles)} carry a scoped capability set smaller than the broadest "
            f"role's {max_cap} capabilities (e.g. {', '.join([str(n) for n in scoped_roles])}), "
            "indicating role-based access control with differentiated privilege levels rather than "
            "blanket administrator access for every account."
        ]
        fail_reasons = []
        recommendations = []
    else:
        pass_reasons = []
        if role_count <= 1:
            fail_reasons = [
                f"Only {role_count} role(s) were returned by the Role Management API, so no "
                "differentiated, scoped role exists alongside the default administrator role."
            ]
        else:
            fail_reasons = [
                f"{role_count} roles exist but none carry a capability set smaller than the "
                f"broadest role's {max_cap} capabilities, meaning every configured role effectively "
                "grants the same blanket level of access."
            ]
        recommendations = [
            "Create Cloud SIEM-specific roles (e.g. Insights viewer, Content editor, Configuration "
            "manager) with capability sets scoped to those functions instead of assigning the full "
            "Administrator capability set to all accounts."
        ]

    result = {
        "isRBACEnabled": is_rbac_enabled,
        "totalRoles": role_count,
        "scopedRoleCount": len(scoped_roles),
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
            "vendor": "Sumo Logic Cloud SIEM",
            "category": "incidentmgmt",
        },
    )
