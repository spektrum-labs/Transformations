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


def find_snappable_nodes(data):
    """Locate the snappableConnection.nodes list, tolerating one or two levels
    of GraphQL 'data' wrapping and the raw envelope root."""
    if isinstance(data, list):
        return data
    if not isinstance(data, dict):
        return []

    candidates = [data]
    inner = data.get("data")
    if isinstance(inner, dict):
        candidates.append(inner)
        inner2 = inner.get("data")
        if isinstance(inner2, dict):
            candidates.append(inner2)

    for cand in candidates:
        conn = cand.get("snappableConnection")
        if isinstance(conn, dict):
            nodes = conn.get("nodes")
            if isinstance(nodes, list):
                return nodes

    for cand in candidates:
        nodes = cand.get("nodes")
        if isinstance(nodes, list):
            return nodes

    return []


def transform(input):
    data, validation = extract_input(input)
    data = data if isinstance(data, (dict, list)) else {}

    nodes = find_snappable_nodes(data)

    total = 0
    in_compliance = 0
    out_of_compliance = 0
    unknown_status = 0
    total_missed_snapshots = 0

    for node in nodes:
        if not isinstance(node, dict):
            continue
        total = total + 1
        status = node.get("complianceStatus")
        if status == "IN_COMPLIANCE":
            in_compliance = in_compliance + 1
        elif status == "OUT_OF_COMPLIANCE":
            out_of_compliance = out_of_compliance + 1
        else:
            unknown_status = unknown_status + 1
        missed = node.get("missedSnapshots") or 0
        if isinstance(missed, int):
            total_missed_snapshots = total_missed_snapshots + missed

    if total == 0:
        compliance_pct = 0.0
    else:
        compliance_pct = round((in_compliance / total) * 100.0, 2)

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if total == 0:
        fail_reasons.append("No snappable (protected object) records were returned to evaluate SLA compliance.")
        recommendations.append("Verify the snappableConnection query returns data for this tenant.")
    else:
        pass_reasons.append(
            f"{in_compliance} of {total} protected objects report complianceStatus='IN_COMPLIANCE' "
            f"({compliance_pct}% SLA compliance rate)."
        )
        if out_of_compliance > 0:
            fail_reasons.append(
                f"{out_of_compliance} of {total} protected objects report complianceStatus='OUT_OF_COMPLIANCE', "
                f"with a combined {total_missed_snapshots} missedSnapshots across all evaluated objects."
            )
            recommendations.append(
                "Review the SLA Domain assignment and recent snapshot activity for objects marked "
                "OUT_OF_COMPLIANCE to identify why RPO windows were missed."
            )
        if unknown_status > 0:
            fail_reasons.append(
                f"{unknown_status} of {total} protected objects report an unrecognized, empty, or missing "
                f"complianceStatus (e.g. 'EMPTY' for unprotected/NoSla objects) and were excluded from the "
                f"compliance numerator."
            )

    result = {
        "backupSlaComplianceRatePercentage": compliance_pct,
        "totalProtectedObjects": total,
        "inComplianceCount": in_compliance,
        "outOfComplianceCount": out_of_compliance,
        "unknownComplianceStatusCount": unknown_status,
        "totalMissedSnapshots": total_missed_snapshots,
    }

    input_summary = {
        "totalProtectedObjects": total,
        "inComplianceCount": in_compliance,
        "outOfComplianceCount": out_of_compliance,
        "unknownComplianceStatusCount": unknown_status,
    }

    metadata = {
        "transformationId": "backupSlaComplianceRatePercentage",
        "vendor": "Rubrik Cloud Vault",
        "category": "backup",
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata=metadata,
    )
