"""Cisco Meraki MX - isFirewallUpdated (THL NW-02: Routine Network Device Patching).

Reads GET /organizations/{orgId}/firmware/upgrades.

Deliberately conservative: it asserts only what the endpoint states. Passes when at
least one upgrade record reports a completed status and none reports a failed,
errored or cancelled one. It does NOT compare version strings or define what
"recent" means -- both would be thresholds this requirement does not state.
"""

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
    criteriaKey = "isFirewallUpdated"
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        if validation.get("status") == "failed":
            return create_response(
                result={criteriaKey: False},
                validation=validation,
                fail_reasons=["Input validation failed"]
            )

        upgrade_records = []

        def collect(obj):
            if isinstance(obj, dict):
                if "items" in obj and isinstance(obj["items"], list):
                    collect(obj["items"])
                elif "status" in obj:
                    upgrade_records.append(obj)
            elif isinstance(obj, list):
                for item in obj:
                    collect(item)

        collect(data)

        completed_count = 0
        failed_count = 0
        pending_count = 0
        failed_statuses = {"failed", "error", "canceled", "cancelled"}

        for record in upgrade_records:
            status = str(record.get("status", "")).strip().lower()

            if status == "completed":
                completed_count += 1
            elif status in failed_statuses:
                failed_count += 1
            else:
                pending_count += 1

        upgrades_evaluated = len(upgrade_records)
        enabled = completed_count > 0 and failed_count == 0

        if enabled:
            pass_reasons = [
                f"{completed_count} completed firmware upgrade record(s) found; no failed upgrades observed."
            ]
            if pending_count > 0:
                pass_reasons.append(
                    f"{pending_count} non-failed upgrade record(s) are still pending or in progress."
                )
            fail_reasons = []
            recommendations = []
        else:
            pass_reasons = []
            if upgrades_evaluated == 0:
                fail_reasons = [
                    "No firmware upgrade records found; routine patching could not be verified."
                ]
                recommendations = [
                    "Ensure firmware upgrade records are available and review device patching operations."
                ]
            elif failed_count > 0:
                fail_reasons = [
                    f"{failed_count} firmware upgrade record(s) are in a failed state; routine patching criteria not met."
                ]
                recommendations = [
                    "Investigate failed firmware upgrades and retry or replace affected network devices."
                ]
            else:
                fail_reasons = [
                    "No completed firmware upgrade records found; routine patching criteria not met."
                ]
                recommendations = [
                    "Review pending or in-progress firmware upgrades to ensure network devices receive routine patches."
                ]

        result = {
            criteriaKey: enabled,
            "completedCount": completed_count,
            "failedCount": failed_count,
            "pendingCount": pending_count,
            "upgradesEvaluated": upgrades_evaluated,
        }

        return create_response(
            result=result,
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={
                "completedCount": completed_count,
                "failedCount": failed_count,
                "pendingCount": pending_count,
                "upgradesEvaluated": upgrades_evaluated,
            },
            metadata={
                "transformationId": criteriaKey,
                "vendor": "Cisco Meraki MX",
                "category": "firewalls",
            },
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
