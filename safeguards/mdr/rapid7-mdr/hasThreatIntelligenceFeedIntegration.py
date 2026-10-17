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
        alerts = data
    elif isinstance(data, dict):
        alerts = data.get("data") or []
        if not isinstance(alerts, list):
            alerts = []
    else:
        alerts = []

    threat_intel_keywords = [
        "threat intelligence",
        "community threat",
        "threat intel",
        "ioc",
        "indicator of compromise",
        "known malicious indicator",
        "threat feed",
        "indicator match",
        "custom threat",
        "threat list",
        "blocklist match",
        "blacklist match",
    ]

    matched_alerts = []
    inspected_fields = []

    for a in alerts:
        if not isinstance(a, dict):
            continue
        fields_to_check = []
        for key in ["alert_type", "alert_type_description", "alert_source", "title"]:
            val = a.get(key)
            if isinstance(val, str):
                fields_to_check.append(val)
        rule = a.get("detection_rule_rrn")
        if isinstance(rule, dict):
            rn = rule.get("rule_name")
            if isinstance(rn, str):
                fields_to_check.append(rn)

        combined = " | ".join(fields_to_check).lower()
        inspected_fields.append(combined)

        for kw in threat_intel_keywords:
            if kw in combined:
                matched_alerts.append({
                    "id": a.get("id"),
                    "alert_type": a.get("alert_type"),
                    "alert_source": a.get("alert_source"),
                    "matched_keyword": kw,
                })
                break

    has_integration = len(matched_alerts) > 0
    total_alerts = len(alerts)

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if has_integration:
        sample = matched_alerts[0]
        pass_reasons.append(
            f"Found {len(matched_alerts)} of {total_alerts} inspected alert(s) referencing threat-intelligence "
            f"sourced detections (e.g. alert id {sample.get('id')}, alert_source="
            f"'{sample.get('alert_source')}', matched keyword '{sample.get('matched_keyword')}')."
        )
    else:
        sample_sources = [a.get("alert_source") for a in alerts if isinstance(a, dict) and a.get("alert_source")][:5]
        fail_reasons.append(
            f"Inspected {total_alerts} investigation alert(s) and found none whose alert_type, "
            f"alert_type_description, alert_source, title, or detection_rule_rrn.rule_name referenced "
            f"threat-intelligence feed indicators (e.g. 'Community Threat', 'IOC', 'threat feed'). "
            f"Sample alert_source values inspected: " + ", ".join(sample_sources)
        )
        recommendations.append(
            "Confirm whether InsightIDR's 'Utilize Existing Threats' Threats REST API has been used to add "
            "custom threat indicators (hashes, IPs, domains) to this tenant; if configured, matching alerts "
            "should surface a Community Threat / threat-intel-sourced alert_type or detection rule."
        )

    result = {
        "hasThreatIntelligenceFeedIntegration": has_integration,
        "totalAlertsInspected": total_alerts,
        "matchedAlertsCount": len(matched_alerts),
    }

    input_summary = {
        "totalAlertsInspected": total_alerts,
        "matchedAlertsCount": len(matched_alerts),
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "hasThreatIntelligenceFeedIntegration",
            "vendor": "Rapid7 MDR",
            "category": "MDR",
        },
    )
