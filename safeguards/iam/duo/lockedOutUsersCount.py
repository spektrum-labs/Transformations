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
        total_objects = len(users)
    elif isinstance(data, dict):
        users = data.get("response") or data.get("data") or []
        if not isinstance(users, list):
            users = []
        metadata_block = data.get("metadata") or {}
        total_objects = metadata_block.get("total_objects") if isinstance(metadata_block, dict) else None
        if not isinstance(total_objects, int):
            total_objects = len(users)
    else:
        users = []
        total_objects = 0

    locked_out_users = []
    for u in users:
        if not isinstance(u, dict):
            continue
        status = u.get("status") or ""
        if isinstance(status, str) and status.strip().lower() == "locked out":
            locked_out_users.append(u)

    locked_out_count = len(locked_out_users)

    sample_usernames = []
    for u in locked_out_users[:5]:
        uname = u.get("username") or u.get("user_id") or "unknown"
        sample_usernames.append(uname)

    input_summary = {
        "totalUsersEvaluated": len(users),
        "totalObjectsReported": total_objects,
        "lockedOutUsersCount": locked_out_count,
    }

    if locked_out_count > 0:
        pass_reasons = [
            f"Found {locked_out_count} user(s) with status='Locked Out' out of {len(users)} users evaluated (fleet total_objects={total_objects}). Examples: {', '.join([str(s) for s in sample_usernames])}."
        ]
        fail_reasons = []
        recommendations = [
            "Review the locked-out accounts in the Duo Admin Panel and either unlock legitimate users or investigate potential brute-force/credential-stuffing activity that triggered the lockout."
        ]
    else:
        pass_reasons = [
            f"No users report status='Locked Out' among {len(users)} users evaluated (fleet total_objects={total_objects})."
        ]
        fail_reasons = []
        recommendations = []

    result = {
        "lockedOutUsersCount": locked_out_count,
        "totalUsersEvaluated": len(users),
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "lockedOutUsersCount",
            "vendor": "Duo",
            "category": "iam",
        },
    )
