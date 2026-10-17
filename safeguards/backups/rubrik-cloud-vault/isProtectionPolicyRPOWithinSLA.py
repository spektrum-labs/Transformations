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
        nodes = data
    elif isinstance(data, dict):
        conn = data.get("snappableConnection") or {}
        if isinstance(conn, list):
            nodes = conn
        else:
            nodes = conn.get("nodes") or []
    else:
        nodes = []

    nodes = [n for n in nodes if isinstance(n, dict)]

    assigned = [n for n in nodes if n.get("slaDomain")]

    total_assigned = len(assigned)
    breaches = []
    compliant = []
    for n in assigned:
        missed = n.get("missedSnapshots") or 0
        compliance = n.get("complianceStatus") or ""
        is_out = (missed and missed > 0) or (compliance and compliance != "IN_COMPLIANCE" and compliance != "InCompliance")
        if is_out:
            breaches.append(n)
        else:
            compliant.append(n)

    breach_count = len(breaches)
    compliant_count = len(compliant)

    within_sla = (total_assigned > 0) and (breach_count == 0)

    input_summary = {
        "totalSnappablesEvaluated": total_assigned,
        "compliantCount": compliant_count,
        "breachCount": breach_count,
        "sampleSize": len(nodes),
    }

    sample_names = [n.get("name") for n in compliant[:5] if n.get("name")]
    sample_breach_names = [n.get("name") for n in breaches[:5] if n.get("name")]

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if total_assigned == 0:
        fail_reasons.append(
            "No snappables with an assigned SLA domain were found in the response sample (sampleSize=%d); RPO compliance cannot be confirmed." % len(nodes)
        )
        recommendations.append("Assign SLA Domains to protected objects and verify snapshot schedules are executing on time.")
    elif within_sla:
        pass_reasons.append(
            f"All {total_assigned} sampled snappables with an assigned SLA Domain report missedSnapshots=0 and complianceStatus=IN_COMPLIANCE (e.g. {', '.join(sample_names) if sample_names else 'sampled objects'})."
        )
    else:
        fail_reasons.append(
            f"{breach_count} of {total_assigned} sampled SLA-assigned snappables have missedSnapshots > 0 or complianceStatus != IN_COMPLIANCE (e.g. {', '.join(sample_breach_names) if sample_breach_names else 'see breaches'}), indicating their most recent snapshot fell outside the RPO window."
        )
        recommendations.append("Investigate missed snapshot jobs on the flagged objects and remediate scheduling or backend cluster issues causing RPO breaches.")

    return create_response(
        result={
            "isProtectionPolicyRPOWithinSLA": within_sla,
            "compliantCount": compliant_count,
            "breachCount": breach_count,
            "totalSnappablesEvaluated": total_assigned,
        },
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={"transformationId": "isProtectionPolicyRPOWithinSLA", "vendor": "Rubrik Cloud Vault", "category": "backup"},
    )
