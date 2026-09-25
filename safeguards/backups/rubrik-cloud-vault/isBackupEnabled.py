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

    nodes = []
    total_count = 0
    if isinstance(data, list):
        nodes = data
    elif isinstance(data, dict):
        snappable_conn = data.get("snappableConnection") or {}
        if isinstance(snappable_conn, dict):
            nodes = snappable_conn.get("nodes") or []
            total_count = snappable_conn.get("count") or 0
        if not nodes:
            nodes = data.get("nodes") or nodes

    if not isinstance(nodes, list):
        nodes = []

    protected_count = 0
    unprotected_count = 0
    sla_assigned_count = 0
    evaluated = 0

    for node in nodes:
        if not isinstance(node, dict):
            continue
        evaluated = evaluated + 1
        protection_status = node.get("protectionStatus")
        sla_domain = node.get("slaDomain")
        if protection_status == "Protected":
            protected_count = protected_count + 1
        else:
            unprotected_count = unprotected_count + 1
        if isinstance(sla_domain, dict) and sla_domain.get("id"):
            sla_assigned_count = sla_assigned_count + 1

    denominator = total_count if total_count else evaluated

    if evaluated == 0:
        is_backup_enabled = False
        fail_reasons = ["No snappable (protected object) records were returned to evaluate SLA Domain assignment."]
        pass_reasons = []
        recommendations = ["Verify the getSnappables query returns data for this tenant."]
    else:
        protected_ratio = protected_count / evaluated
        is_backup_enabled = protected_ratio >= 0.99 and unprotected_count == 0
        if is_backup_enabled:
            pass_reasons = [
                f"All {evaluated} evaluated protected objects report protectionStatus='Protected' with an SLA Domain assigned (sla_assigned_count={sla_assigned_count})."
            ]
            fail_reasons = []
            recommendations = []
        else:
            pass_reasons = []
            fail_reasons = [
                f"{unprotected_count} of {evaluated} evaluated objects do not report protectionStatus='Protected' (protected_count={protected_count}, sla_assigned_count={sla_assigned_count})."
            ]
            recommendations = [
                "Assign an SLA Domain to all unprotected objects to activate scheduled snapshot capture into Rubrik Cloud Vault."
            ]

    result = {
        "isBackupEnabled": is_backup_enabled,
        "protectedCount": protected_count,
        "unprotectedCount": unprotected_count,
        "evaluatedCount": evaluated,
        "fleetTotalCount": total_count,
    }

    input_summary = {
        "evaluatedCount": evaluated,
        "protectedCount": protected_count,
        "unprotectedCount": unprotected_count,
        "fleetTotalCount": total_count,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "isBackupEnabled",
            "vendor": "Rubrik Cloud Vault",
            "category": "backup",
        },
    )
