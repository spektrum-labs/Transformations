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
        if isinstance(conn, dict):
            nodes = conn.get("nodes") or []
        else:
            nodes = data.get("nodes") or data.get("data") or []
    else:
        nodes = []

    if not isinstance(nodes, list):
        nodes = []

    critical_nodes = []
    for n in nodes:
        if not isinstance(n, dict):
            continue
        object_type = n.get("objectType") or ""
        if "database" in object_type.lower():
            critical_nodes.append(n)

    total_critical = len(critical_nodes)
    protected_critical = 0
    unprotected_names = []
    for n in critical_nodes:
        sla = n.get("slaDomain") or {}
        has_sla = isinstance(sla, dict) and bool(sla.get("id"))
        protection = n.get("protectionStatus") or ""
        if has_sla and protection == "Protected":
            protected_critical = protected_critical + 1
        else:
            name = n.get("name") or n.get("id") or "unknown"
            unprotected_names.append(name)

    if total_critical == 0:
        is_enabled = False
        pass_reasons = []
        fail_reasons = [
            "No objects with objectType containing 'Database' were found in this snappable "
            "page sample (%d total objects inspected), so critical-system backup coverage "
            "could not be confirmed." % len(nodes)
        ]
        recommendations = [
            "Verify that critical database workloads are onboarded into Rubrik and visible via "
            "snappableConnection; if this page is a partial sample, re-run against a page containing "
            "the critical workloads."
        ]
    else:
        is_enabled = protected_critical == total_critical
        if is_enabled:
            pass_reasons = [
                "All %d database-type objects (objectType containing 'Database') in this sample have "
                "protectionStatus='Protected' and a non-empty slaDomain assignment." % total_critical
            ]
            fail_reasons = []
            recommendations = []
        else:
            pass_reasons = []
            fail_reasons = [
                "%d of %d database-type critical objects lack an actively assigned SLA domain or are not "
                "protectionStatus='Protected'. Examples: %s" % (
                    total_critical - protected_critical,
                    total_critical,
                    ", ".join(unprotected_names[:5]),
                )
            ]
            recommendations = [
                "Assign an SLA Domain to unprotected critical database objects (%s) so they are actively "
                "protected." % ", ".join(unprotected_names[:5])
            ]

    result = {
        "isBackupEnabledForCriticalSystems": is_enabled,
        "totalCriticalObjects": total_critical,
        "protectedCriticalObjects": protected_critical,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={
            "totalObjectsInPage": len(nodes),
            "criticalObjectsFound": total_critical,
            "criticalObjectsProtected": protected_critical,
        },
        metadata={
            "transformationId": "isBackupEnabledForCriticalSystems",
            "vendor": "Rubrik Cloud Vault",
            "category": "backup",
        },
    )
