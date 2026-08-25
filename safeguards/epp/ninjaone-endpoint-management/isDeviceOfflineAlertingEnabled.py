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

    policies = data.get("data") or data.get("policies") or []
    if not isinstance(policies, list):
        policies = []

    keywords = ["offline", "device down", "devicedown"]

    matched_policy_names = []
    for p in policies:
        if not isinstance(p, dict):
            continue
        text_parts = []
        name_val = p.get("name")
        if isinstance(name_val, str):
            text_parts.append(name_val.lower())
        desc_val = p.get("description")
        if isinstance(desc_val, str):
            text_parts.append(desc_val.lower())
        conditions = p.get("conditions") or []
        if isinstance(conditions, list):
            for c in conditions:
                if isinstance(c, dict):
                    ct = c.get("conditionType") or c.get("type") or c.get("name") or ""
                    if isinstance(ct, str):
                        text_parts.append(ct.lower())
        combined = " ".join(text_parts)
        is_match = False
        for k in keywords:
            if k in combined:
                is_match = True
        if is_match:
            label = p.get("name") or p.get("id") or "unknown"
            matched_policy_names.append(label)

    total_policies = len(policies)
    is_enabled = len(matched_policy_names) > 0

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if total_policies == 0:
        fail_reasons.append(
            "No policies were returned by getPolicies, so no Device Down / offline alerting condition could be confirmed."
        )
        recommendations.append(
            "Verify at least one NinjaOne policy is configured with a Device Down condition, and confirm getPolicies is returning policy data for this tenant."
        )
    elif is_enabled:
        sample = matched_policy_names[:5]
        pass_reasons.append(
            f"Found {len(matched_policy_names)} of {total_policies} policies with a name/description/condition referencing offline or device-down alerting: {sample}."
        )
    else:
        fail_reasons.append(
            f"Scanned {total_policies} policies returned by getPolicies; none had a name, description, or condition entry referencing offline / device-down alerting."
        )
        recommendations.append(
            "Add a Device Down condition to at least one assigned policy so technicians are alerted when a device has been offline beyond a configured duration."
        )

    result = {
        "isDeviceOfflineAlertingEnabled": is_enabled,
        "totalPolicies": total_policies,
        "matchedPolicyCount": len(matched_policy_names),
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={"totalPolicies": total_policies, "matchedPolicyCount": len(matched_policy_names)},
        metadata={
            "transformationId": "isDeviceOfflineAlertingEnabled",
            "vendor": "NinjaOne Endpoint Management",
            "category": "epp",
        },
    )
