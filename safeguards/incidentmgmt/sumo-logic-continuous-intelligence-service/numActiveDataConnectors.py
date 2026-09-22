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

    collectors = data.get("collectors") or []
    if not isinstance(collectors, list):
        collectors = []

    total_collectors = len(collectors)
    active_collectors = [c for c in collectors if isinstance(c, dict) and c.get("alive") is True]
    active_count = len(active_collectors)

    active_names = [c.get("name") for c in active_collectors if c.get("name")]
    inactive_names = [c.get("name") for c in collectors if isinstance(c, dict) and c.get("alive") is not True and c.get("name")]

    if total_collectors == 0:
        pass_reasons = []
        fail_reasons = ["No collectors were returned by GET /v1/collectors, so no active data connectors could be confirmed."]
        recommendations = ["Verify that at least one Installed or Hosted Collector is configured to forward data into Cloud SIEM."]
    else:
        sample = ", ".join(active_names[:5]) if active_names else "none"
        pass_reasons = [
            f"{active_count} of {total_collectors} collectors report alive=true in GET /v1/collectors (e.g. {sample})."
        ]
        fail_reasons = []
        if inactive_names:
            recommendations = [
                f"Investigate offline collectors ({', '.join(inactive_names[:5])}) reporting alive=false to restore data ingestion."
            ]
        else:
            recommendations = []

    result = {
        "numActiveDataConnectors": active_count,
        "totalCollectors": total_collectors,
        "activeCollectorNames": active_names,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={"totalCollectors": total_collectors, "activeCollectors": active_count},
        metadata={
            "transformationId": "numActiveDataConnectors",
            "vendor": "Sumo Logic Continuous Intelligence Service",
            "category": "incidentmgmt",
        },
    )
