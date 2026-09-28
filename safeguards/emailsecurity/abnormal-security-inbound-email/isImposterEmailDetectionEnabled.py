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

    messages = []
    if isinstance(data, dict):
        messages = data.get("messages") or []
    elif isinstance(data, list):
        messages = data

    total_messages = len(messages)
    classified_count = 0
    impersonation_signal_count = 0
    attack_types_seen = []
    attack_strategies_seen = []
    impersonated_parties_seen = []

    for m in messages:
        if not isinstance(m, dict):
            continue
        attack_type = m.get("attackType")
        attack_strategy = m.get("attackStrategy")
        impersonated_party = m.get("impersonatedParty")

        if attack_type and attack_strategy:
            classified_count = classified_count + 1

        if attack_type:
            if attack_type not in attack_types_seen:
                attack_types_seen.append(attack_type)
        if attack_strategy:
            if attack_strategy not in attack_strategies_seen:
                attack_strategies_seen.append(attack_strategy)
        if impersonated_party:
            if impersonated_party not in impersonated_parties_seen:
                impersonated_parties_seen.append(impersonated_party)

        impersonation_keywords = ["impersonation", "spoof", "bec", "invoice", "payment fraud", "executive"]
        strategy_lower = (attack_strategy or "").lower()
        type_lower = (attack_type or "").lower()
        is_impersonation_flavoured = False
        for kw in impersonation_keywords:
            if kw in strategy_lower or kw in type_lower:
                is_impersonation_flavoured = True
        if impersonated_party and impersonated_party not in ["None / Others", "None", ""]:
            is_impersonation_flavoured = True

        if is_impersonation_flavoured:
            impersonation_signal_count = impersonation_signal_count + 1

    is_enabled = total_messages > 0 and classified_count == total_messages

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if is_enabled:
        pass_reasons.append(
            f"All {total_messages} inspected message(s) carry populated attackType and attackStrategy "
            f"classification fields (attackTypes observed: {attack_types_seen}, attackStrategies observed: "
            f"{attack_strategies_seen}), demonstrating Abnormal's behavioral AI actively classifies inbound "
            f"messages including an impersonatedParty field (values observed: {impersonated_parties_seen}) "
            f"used specifically for imposter/BEC detection."
        )
        if impersonation_signal_count > 0:
            pass_reasons.append(
                f"{impersonation_signal_count} of {total_messages} message(s) carried impersonation/BEC-flavoured "
                f"classification signals (non-default impersonatedParty or attackType/attackStrategy keywords)."
            )
    else:
        if total_messages == 0:
            fail_reasons.append("No threat message records were present in the response to evaluate classification fields.")
            recommendations.append("Verify the tenant has threat data and that the threat detail endpoint is reachable.")
        else:
            fail_reasons.append(
                f"Only {classified_count} of {total_messages} message(s) carried both attackType and "
                f"attackStrategy classification fields; imposter/BEC classification does not appear consistently active."
            )
            recommendations.append(
                "Confirm Abnormal's behavioral AI detection engine is enabled and fully licensed for this tenant."
            )

    result = {
        "isImposterEmailDetectionEnabled": is_enabled,
        "totalMessagesEvaluated": total_messages,
        "classifiedMessages": classified_count,
        "impersonationFlavouredMessages": impersonation_signal_count,
    }

    input_summary = {
        "totalMessagesEvaluated": total_messages,
        "classifiedMessages": classified_count,
        "attackTypesObserved": attack_types_seen,
        "attackStrategiesObserved": attack_strategies_seen,
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
