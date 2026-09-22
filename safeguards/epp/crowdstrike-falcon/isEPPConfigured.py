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

    api_errors = []
    if data.get("error") is True or data.get("statusCode") == 500 or data.get("status") == "Error":
        msg = data.get("errorMessage") or data.get("message") or "Unknown API error"
        api_errors.append(f"Vendor API returned an error: {msg}")

    resources = data.get("resources") or []
    if not isinstance(resources, list):
        resources = []

    total_policies = len(resources)
    configured_policies = []
    for p in resources:
        if not isinstance(p, dict):
            continue
        enabled = bool(p.get("enabled"))
        groups = p.get("groups") or []
        prevention_settings = p.get("prevention_settings") or []
        has_groups = isinstance(groups, list) and len(groups) > 0
        has_settings = isinstance(prevention_settings, list) and len(prevention_settings) > 0
        if enabled and has_groups and has_settings:
            configured_policies.append(p)

    is_configured = len(configured_policies) > 0

    input_summary = {
        "totalPreventionPolicies": total_policies,
        "configuredPreventionPolicies": len(configured_policies),
    }

    if api_errors:
        return create_response(
            result={"isEPPConfigured": False},
            validation=validation,
            fail_reasons=[
                "Unable to retrieve prevention policy data from CrowdStrike Falcon API; "
                "cannot confirm an enabled prevention policy assigned to a host group."
            ],
            recommendations=[
                "Investigate the getCombinedPreventionPolicies API integration error and re-run "
                "the scan once the vendor API responds successfully."
            ],
            input_summary=input_summary,
            api_errors=api_errors,
            metadata={
                "transformationId": "isEPPConfigured",
                "vendor": "CrowdStrike Falcon",
                "category": "epp",
            },
        )

    if is_configured:
        names = [p.get("name") for p in configured_policies if p.get("name")]
        sample_names = ", ".join([str(n) for n in names[:3]]) if names else "unnamed policy"
        pass_reasons = [
            f"Found {len(configured_policies)} of {total_policies} prevention policy(ies) with "
            f"enabled=true, non-empty prevention_settings, and assigned host groups "
            f"(e.g. {sample_names}), confirming EPP is configured and assigned to a host group "
            f"covering the endpoint population."
        ]
        fail_reasons = []
        recommendations = []
    else:
        pass_reasons = []
        if total_policies == 0:
            fail_reasons = [
                "No prevention policies were returned by getCombinedPreventionPolicies; "
                "there is no Prevention Policy record to confirm EPP configuration."
            ]
        else:
            fail_reasons = [
                f"Found {total_policies} prevention policy(ies), but none had enabled=true "
                f"together with non-empty prevention_settings and at least one assigned host group."
            ]
        recommendations = [
            "Create or enable a CrowdStrike Falcon Prevention Policy, configure its "
            "prevention_settings (NGAV/ML detection toggles), and assign it to the host group "
            "covering this endpoint population."
        ]

    return create_response(
        result={"isEPPConfigured": is_configured},
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "isEPPConfigured",
            "vendor": "CrowdStrike Falcon",
            "category": "epp",
        },
    )
