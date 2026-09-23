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
        devices = data
    elif isinstance(data, dict):
        devices = data.get("data") or data.get("devices") or data.get("results") or []
        if not isinstance(devices, list):
            devices = []
    else:
        devices = []

    total = len(devices)
    covered = 0
    uncovered_samples = []
    for d in devices:
        if not isinstance(d, dict):
            continue
        policy_id = d.get("policyId")
        role_policy_id = d.get("rolePolicyId")
        has_policy = (policy_id is not None) or (role_policy_id is not None)
        if has_policy:
            covered = covered + 1
        else:
            if len(uncovered_samples) < 5:
                name = d.get("systemName") or d.get("displayName") or str(d.get("id"))
                uncovered_samples.append(name)

    if total == 0:
        percentage = 0
    else:
        percentage = round((covered / total) * 100.0, 2)

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if total == 0:
        fail_reasons.append("No devices were returned by getDevices, so policy coverage cannot be confirmed.")
        recommendations.append("Verify the getDevices API call returns the managed device fleet.")
    elif percentage >= 100.0:
        pass_reasons.append(
            f"All {total} managed devices carry a policyId (device/override) or rolePolicyId "
            f"(role-based default policy), giving {covered}/{total} devices ({percentage}%) with a security policy assigned."
        )
    else:
        fail_reasons.append(
            f"Only {covered} of {total} managed devices ({percentage}%) have a policyId or rolePolicyId set; "
            f"{total - covered} devices show neither field populated."
        )
        if uncovered_samples:
            recommendations.append(
                f"Assign an organization default, location, or device-level policy to unpoliced devices such as: "
                f"{', '.join([str(s) for s in uncovered_samples])}."
            )
        else:
            recommendations.append("Assign an organization default, location, or device-level policy to all unpoliced devices.")

    return create_response(
        result={
            "requiredCoveragePercentage": percentage,
            "devicesWithPolicy": covered,
            "totalDevices": total,
        },
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={"totalDevices": total, "devicesWithPolicy": covered},
        metadata={
            "transformationId": "requiredCoveragePercentage",
            "vendor": "NinjaOne",
            "category": "epp",
        },
    )
