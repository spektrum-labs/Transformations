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
        policies = data
    elif isinstance(data, dict):
        policies = data.get("resources") or data.get("data") or []
    else:
        policies = []

    if not isinstance(policies, list):
        policies = []

    total_policies = len(policies)
    assigned_policies = [p for p in policies if isinstance(p, dict) and (p.get("groups") or [])]
    assigned_enabled = [p for p in assigned_policies if p.get("enabled") is True]
    assigned_disabled = [p for p in assigned_policies if p.get("enabled") is not True]

    total_assigned = len(assigned_policies)
    total_assigned_enabled = len(assigned_enabled)
    total_assigned_disabled = len(assigned_disabled)

    if total_assigned == 0:
        is_enabled = False
        fail_reasons = [
            f"No prevention policies with an assigned host group ('groups' non-empty) were found among {total_policies} policies returned; cannot confirm an enabled prevention policy is active on any host group."
        ]
        pass_reasons = []
        recommendations = [
            "Assign an enabled prevention policy to at least one host group in the CrowdStrike Falcon console."
        ]
    elif total_assigned_disabled == 0:
        is_enabled = True
        names = [p.get("name") for p in assigned_enabled][:5]
        pass_reasons = [
            f"All {total_assigned} prevention policies assigned to a host group have enabled=true (examples: {names}), out of {total_policies} total prevention policies."
        ]
        fail_reasons = []
        recommendations = []
    else:
        is_enabled = False
        disabled_names = [p.get("name") for p in assigned_disabled][:5]
        pass_reasons = []
        fail_reasons = [
            f"{total_assigned_disabled} of {total_assigned} host-group-assigned prevention policies have enabled=false (examples: {disabled_names})."
        ]
        recommendations = [
            f"Enable the prevention policy top-level flag for the following disabled but host-group-assigned policies: {disabled_names}."
        ]

    result = {
        "isEPPEnabled": is_enabled,
        "totalPreventionPolicies": total_policies,
        "assignedPreventionPolicies": total_assigned,
        "assignedEnabledPolicies": total_assigned_enabled,
        "assignedDisabledPolicies": total_assigned_disabled,
    }

    input_summary = {
        "totalPreventionPolicies": total_policies,
        "assignedPreventionPolicies": total_assigned,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "isEPPEnabled",
            "vendor": "CrowdStrike Falcon",
            "category": "epp",
        },
    )
