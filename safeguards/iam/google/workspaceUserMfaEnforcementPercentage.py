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
        users = data
    elif isinstance(data, dict):
        users = data.get("users") or data.get("data") or []
    else:
        users = []

    if not isinstance(users, list):
        users = []

    active_users = [u for u in users if isinstance(u, dict) and not u.get("suspended") and not u.get("archived")]
    total_active = len(active_users)
    enforced_count = sum(1 for u in active_users if u.get("isEnforcedIn2Sv") is True)

    if total_active == 0:
        pct = 0.0
        fail_reasons = ["No active (non-suspended, non-archived) users found in the listUsers response; cannot compute enforcement percentage."]
        pass_reasons = []
        recommendations = ["Verify the Directory API users.list call returns active users for this domain."]
    else:
        pct = round((enforced_count / total_active) * 100.0, 2)
        if pct >= 100.0:
            pass_reasons = [
                "All %d active users report isEnforcedIn2Sv=true out of %d active users evaluated." % (enforced_count, total_active)
            ]
            fail_reasons = []
            recommendations = []
        else:
            pass_reasons = []
            not_enforced = total_active - enforced_count
            fail_reasons = [
                "%d of %d active users (%.2f%%) report isEnforcedIn2Sv=true; %d active users do not have 2-Step Verification enforced." % (enforced_count, total_active, pct, not_enforced)
            ]
            recommendations = [
                "Enable 2-Step Verification enforcement for the remaining %d active users via Admin console Security > 2-Step Verification, or apply an org-unit enforcement policy covering all active users." % not_enforced
            ]

    result = {
        "workspaceUserMfaEnforcementPercentage": pct,
        "activeUsersEvaluated": total_active,
        "activeUsersWithEnforcement": enforced_count,
    }

    input_summary = {
        "totalUsersInResponse": len(users),
        "activeUsersEvaluated": total_active,
        "activeUsersWithEnforcement": enforced_count,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "workspaceUserMfaEnforcementPercentage",
            "vendor": "Google",
            "category": "iam",
        },
    )
