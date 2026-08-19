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

    mode = data.get("mode")
    ids_rulesets = data.get("idsRulesets") or []
    protected_networks = data.get("protectedNetworks") or {}

    ips_enabled = mode == "prevention"

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    input_summary = {
        "mode": mode,
        "idsRulesetsCount": len(ids_rulesets) if isinstance(ids_rulesets, list) else 0,
    }

    if mode is None:
        fail_reasons.append(
            "No 'mode' field found in the intrusion detection/prevention settings response; "
            "unable to confirm the MX network's IDS/IPS mode."
        )
        recommendations.append(
            "Configure the network's intrusion detection/prevention settings and set mode to 'prevention'."
        )
    elif ips_enabled:
        pass_reasons.append(
            f"Network intrusion settings report mode='{mode}', indicating the appliance is "
            f"actively blocking traffic matching intrusion signatures (not just detecting/logging it)."
        )
        if ids_rulesets:
            pass_reasons.append(
                f"idsRulesets configured: {ids_rulesets}."
            )
    else:
        fail_reasons.append(
            f"Network intrusion settings report mode='{mode}', which is not 'prevention'. "
            f"The IDS/IPS engine is either disabled or running in detection-only mode."
        )
        recommendations.append(
            "Set the appliance intrusion detection/prevention mode to 'prevention' in the "
            "Meraki Dashboard (Security & SD-WAN > Threat protection) to actively block malicious traffic."
        )

    result = {
        "ipsEnabled": ips_enabled,
        "mode": mode,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "ipsEnabled",
            "vendor": "Cisco Meraki MX",
            "category": "Firewalls",
        },
    )
