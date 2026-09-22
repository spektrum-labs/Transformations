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
    data = data if isinstance(data, (dict, list)) else {}

    if isinstance(data, list):
        threats = data
        total = len(threats)
    else:
        threats = data.get("threats") or []
        if not isinstance(threats, list):
            threats = []
        total = data.get("total")
        if not isinstance(total, int):
            total = len(threats)

    # Look for direct attackType / impersonatedParty evidence if the sample carries it
    attack_type_samples = []
    for t in threats:
        if isinstance(t, dict):
            at = t.get("attackType")
            ip = t.get("impersonatedParty")
            if at or ip:
                attack_type_samples.append({"attackType": at, "impersonatedParty": ip})

    is_enabled = total > 0
    input_summary = {
        "totalThreats": total,
        "threatsInPage": len(threats),
        "threatsWithAttackTypeEvidence": len(attack_type_samples),
    }

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if is_enabled:
        if attack_type_samples:
            sample = attack_type_samples[0]
            pass_reasons.append(
                "Threat feed at /v1/threats returned %d total classified threats (total=%d); "
                "sample message carries attackType=%r / impersonatedParty=%r, confirming Abnormal's "
                "behavioral AI is actively classifying inbound messages for impersonation/BEC patterns."
                % (total, total, sample.get("attackType"), sample.get("impersonatedParty"))
            )
        else:
            pass_reasons.append(
                "Threat feed at /v1/threats returned total=%d classified threats across %d threatIds "
                "in this page, evidencing that Abnormal's inbound threat detection pipeline (which "
                "classifies messages by attackType including impersonation and BEC) is active and "
                "producing threat records for this tenant." % (total, len(threats))
            )
    else:
        fail_reasons.append(
            "The /v1/threats endpoint returned total=0 threats, so no evidence of active "
            "imposter/BEC email classification could be observed for this tenant."
        )
        recommendations.append(
            "Confirm the Abnormal Security inbound email product is provisioned and actively "
            "scanning mail flow for this tenant; if threats are expected, verify the API token "
            "has access to the correct mailbox/tenant scope."
        )

    result = {
        "isImposterEmailDetectionEnabled": is_enabled,
        "totalThreats": total,
        "threatsWithAttackTypeEvidence": len(attack_type_samples),
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "isImposterEmailDetectionEnabled",
            "vendor": "Abnormal Security Inbound Email",
            "category": "emailsecurity",
        },
    )
