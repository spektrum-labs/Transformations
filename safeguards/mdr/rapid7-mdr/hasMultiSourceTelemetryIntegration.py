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


def classify_telemetry_type(name):
    name_lower = (name or "").lower()
    categories = []
    endpoint_kw = ["falcon", "crowdstrike", "edr", "defender", "sentinelone", "carbonblack", "cylance", "sophos", "cb.", "s1."]
    network_kw = ["dns", "dhcp", "-fw", "fw1", "fw2", "firewall", "vpn", "proxy", "switch", "router", "palo", "fortinet", "checkpoint", "ips", "ids"]
    cloud_kw = ["aws", "azure", "o365", "office365", "gcp", "google", "cloudtrail", "s3-", "cloud", "salesforce", "workday"]
    identity_kw = ["-dc", "dc19", "dc22", "dc01", "domain controller", "ldap", "okta", "adfs", "auth", "sso", "idp", "activedirectory"]
    for kw in endpoint_kw:
        if kw in name_lower:
            categories.append("endpoint")
            break
    for kw in network_kw:
        if kw in name_lower:
            categories.append("network")
            break
    for kw in cloud_kw:
        if kw in name_lower:
            categories.append("cloud")
            break
    for kw in identity_kw:
        if kw in name_lower:
            categories.append("identity")
            break
    return categories


def transform(input):
    data, validation = extract_input(input)
    data = data if isinstance(data, (dict, list)) else {}
    if isinstance(data, list):
        logs = data
    elif isinstance(data, dict):
        logs = data.get("logs") or data.get("data") or []
    else:
        logs = []

    category_counts = {"endpoint": 0, "network": 0, "cloud": 0, "identity": 0}
    category_examples = {"endpoint": [], "network": [], "cloud": [], "identity": []}
    total_logs = 0
    for log in logs:
        if not isinstance(log, dict):
            continue
        total_logs = total_logs + 1
        name = log.get("name") or ""
        cats = classify_telemetry_type(name)
        for c in cats:
            category_counts[c] = category_counts[c] + 1
            if len(category_examples[c]) < 3:
                category_examples[c].append(name)

    distinct_categories = [c for c in category_counts if category_counts[c] > 0]
    source_type_count = len(distinct_categories)
    has_multi_source = source_type_count >= 2

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if has_multi_source:
        details = ", ".join([f"{c}={category_counts[c]}" for c in distinct_categories])
        examples_str = "; ".join([f"{c}: {category_examples[c]}" for c in distinct_categories])
        pass_reasons.append(
            f"Log Search management API (/log_search/management/logs) returned {total_logs} configured log sources spanning {source_type_count} distinct telemetry types ({details}). Examples: {examples_str}"
        )
    else:
        if total_logs == 0:
            fail_reasons.append("Log Search management API (/log_search/management/logs) returned 0 configured log sources.")
            recommendations.append("Configure at least two distinct telemetry sources (e.g. endpoint EDR, network firewall/DNS, identity domain controllers, or cloud services) to feed InsightIDR.")
        else:
            details = ", ".join([f"{c}={category_counts[c]}" for c in distinct_categories]) if distinct_categories else "none classified"
            fail_reasons.append(f"Log Search management API returned {total_logs} configured log sources, but only {source_type_count} distinct telemetry type(s) could be identified from log names ({details}).")
            recommendations.append("Onboard additional telemetry sources covering multiple categories (endpoint, network, cloud, identity) to satisfy multi-source telemetry integration.")

    result = {
        "hasMultiSourceTelemetryIntegration": has_multi_source,
        "totalLogSources": total_logs,
        "distinctTelemetryTypeCount": source_type_count,
        "telemetryTypeCounts": category_counts,
    }

    input_summary = {
        "totalLogSources": total_logs,
        "distinctTelemetryTypeCount": source_type_count,
    }

    validation_result = {
        "status": validation.get("status", "unknown") if isinstance(validation, dict) else "unknown",
        "errors": validation.get("errors", []) if isinstance(validation, dict) else [],
        "warnings": validation.get("warnings", []) if isinstance(validation, dict) else [],
    }

    return create_response(
        result=result,
        validation=validation_result,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "hasMultiSourceTelemetryIntegration",
            "vendor": "Rapid7 MDR",
            "category": "mdr",
        },
    )
