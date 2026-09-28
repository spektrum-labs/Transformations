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

    if isinstance(data, dict):
        stat = data.get("stat")
        codes = data.get("response")
        codes = codes if isinstance(codes, list) else []
        metadata = data.get("metadata") or {}
        total_objects = metadata.get("total_objects")
    elif isinstance(data, list):
        stat = "OK"
        codes = data
        total_objects = len(data)
    else:
        stat = None
        codes = []
        total_objects = None

    has_access = bool(stat == "OK" or (isinstance(data, dict) and "response" in data))

    bypass_code_count = len(codes)

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if has_access:
        pass_reasons.append(
            f"Duo Admin API endpoint /admin/v1/users/{{user_id}}/bypass_codes responded with stat='{stat}' "
            f"and a 'response' array (bypass_code_count={bypass_code_count}, total_objects={total_objects}), "
            f"demonstrating that emergency access (bypass) code data is reachable via the API."
        )
    else:
        fail_reasons.append(
            f"Call to /admin/v1/users/{{user_id}}/bypass_codes did not return a usable envelope "
            f"(stat={stat!r}); could not confirm emergency access code API access."
        )
        recommendations.append(
            "Verify the Duo Admin API credential has permission to call the Retrieve Bypass Codes endpoint."
        )

    result = {
        "hasEmergencyAccessCodeAPIAccess": has_access,
        "bypassCodeCount": bypass_code_count,
    }

    input_summary = {
        "stat": stat,
        "bypassCodeCount": bypass_code_count,
        "totalObjectsReported": total_objects,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "hasEmergencyAccessCodeAPIAccess",
            "vendor": "Duo",
            "category": "iam",
        },
    )
