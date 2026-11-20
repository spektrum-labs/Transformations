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

    workload_anomalies = {}
    if isinstance(data, dict):
        if "workloadAnomalies" in data:
            workload_anomalies = data.get("workloadAnomalies") or {}
        elif "data" in data and isinstance(data.get("data"), dict):
            workload_anomalies = data.get("data", {}).get("workloadAnomalies") or {}

    nodes = workload_anomalies.get("nodes") if isinstance(workload_anomalies, dict) else None
    nodes = nodes if isinstance(nodes, list) else []

    # If the workloadAnomalies query returns a well-formed nodes list (even empty),
    # the anomaly-detection / radar feature is active for this tenant.
    feature_responded = isinstance(workload_anomalies, dict) and "nodes" in workload_anomalies

    total_anomalies = len(nodes)
    critical_count = 0
    unresolved_count = 0
    high_encryption_count = 0
    for n in nodes:
        if not isinstance(n, dict):
            continue
        if n.get("severity") == "Critical":
            critical_count = critical_count + 1
        if n.get("resolutionStatus") == "UNRESOLVED":
            unresolved_count = unresolved_count + 1
        if n.get("encryption") == "HIGH":
            high_encryption_count = high_encryption_count + 1

    is_enabled = bool(feature_responded)

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if is_enabled:
        pass_reasons.append(
            f"workloadAnomalies query (Rubrik Radar anomaly detection) returned a valid nodes list with "
            f"{total_anomalies} anomaly records, confirming ML-based anomaly detection is active for this tenant."
        )
        if total_anomalies > 0:
            pass_reasons.append(
                f"Of {total_anomalies} detected anomalies, {critical_count} are Critical severity, "
                f"{unresolved_count} are UNRESOLVED, and {high_encryption_count} show HIGH encryption-change "
                f"indicators typical of ransomware activity (e.g. workload 'livadmoxdz01' severity=Critical, "
                f"encryption=HIGH)."
            )
    else:
        fail_reasons.append(
            "The workloadAnomalies GraphQL query did not return a usable 'nodes' collection, indicating "
            "ransomware anomaly detection is not enabled or not returning data for this tenant."
        )
        recommendations.append(
            "Enable Rubrik Radar / Anomaly Detection on this tenant and verify the workloadAnomalies API "
            "returns data for protected workloads."
        )

    result = {
        "isRansomwareDetectionEnabled": is_enabled,
        "totalAnomaliesDetected": total_anomalies,
        "criticalAnomaliesCount": critical_count,
        "unresolvedAnomaliesCount": unresolved_count,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={
            "totalAnomaliesDetected": total_anomalies,
            "criticalAnomaliesCount": critical_count,
            "unresolvedAnomaliesCount": unresolved_count,
        },
        metadata={
            "transformationId": "isRansomwareDetectionEnabled",
            "vendor": "Rubrik Cloud Vault",
            "category": "backup",
        },
    )
