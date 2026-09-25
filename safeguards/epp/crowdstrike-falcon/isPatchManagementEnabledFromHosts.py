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


def as_int(value):
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def is_rfm(value):
    return value is True or str(value).strip().lower() in ("yes", "true")


def update_mode(sensor_update):
    """Read a host's sensor-update settings_hash: "auto", "pinned", "off", "none" or "unknown".

    The hash is "<build>;<n>". Measured 2026-09-25 against the sensor-update policies on 5 Falcon
    tenants (about 10,000 hosts): every host whose policy build is a tagged release (N, N-1, N-2,
    for example "21309|n-1|tagged|1") reports "tagged|<tag>;..."; a pinned build reports
    "<digits>;..."; an empty build (sensor version updates off) reports ";...". Anything else is
    "unknown" and the key is not measured, rather than guessed.
    """
    if not isinstance(sensor_update, dict) or not sensor_update.get("policy_id"):
        return "none"
    build = str(sensor_update.get("settings_hash") or "").split(";")[0]
    if build.startswith("tagged|") and build[len("tagged|"):].isdigit():
        return "auto"
    if build == "":
        return "off" if ";" in str(sensor_update.get("settings_hash") or "") else "unknown"
    if build.isdigit():
        return "pinned"
    return "unknown"


def transform(input):
    """
    isPatchManagementEnabled (CrowdStrike, from GET /devices/combined/devices/v1, Hosts: Read).

    True when every active Falcon sensor has automatic sensor updates on: the sensor-update policy
    applied to the host tracks a tagged CrowdStrike release (N, N-1 or N-2) rather than a pinned
    build or "sensor version updates off". It reads each host's device_policies.sensor_update, so it
    needs no Sensor update policies scope.

    Active means what requiredCoveragePercentage counts: status "normal", not in reduced
    functionality mode, an agent_version and a last_seen. Mobile hosts have no sensor-update policy
    and are left out. Not measured (dataCollection error) on an API error, a truncated device list,
    no resources list or a record that is not a host, or a settings_hash in a shape not recognised.
    """
    if isinstance(input, bytes):
        input = input.decode("utf-8")
    if isinstance(input, str):
        try:
            input = json.loads(input) if input.strip() else None
        except ValueError:
            input = None
    data, validation = extract_input(input)
    data = data if isinstance(data, dict) else {}

    api_errors = []
    if data.get("error") or data.get("errorType") == "internal" or str(data.get("status", "")).lower() == "error":
        msg = data.get("errorMessage") or data.get("message") or "Unknown API error"
        api_errors.append(f"CrowdStrike API returned an error: {msg}")

    resources = data.get("resources")
    if not isinstance(resources, list):
        if not api_errors:
            api_errors.append("Response has no resources list; not a Falcon host list")
        resources = []

    meta = data.get("meta") if isinstance(data.get("meta"), dict) else {}
    pagination = meta.get("pagination") if isinstance(meta.get("pagination"), dict) else {}
    reported_total = as_int(pagination.get("total"))
    truncated_flag = pagination.get("truncated") is True or str(pagination.get("truncated")).strip().lower() == "true"
    if not api_errors and ((reported_total is not None and reported_total > len(resources)) or truncated_flag):
        api_errors.append(
            f"Device list was truncated: {len(resources)} of {reported_total if reported_total is not None else 'unknown'} "
            "devices returned; not evaluated on a sample"
        )
    if not api_errors and any(not isinstance(d, dict) or not d.get("device_id") for d in resources):
        api_errors.append("Response is not a Falcon host list (a record has no device_id); check the method wiring")

    counts = {"auto": 0, "pinned": 0, "off": 0, "none": 0, "unknown": 0}
    judged = 0
    pending = 0
    skipped_mobile = 0
    skipped_inactive = 0
    if not api_errors:
        for device in resources:
            platform = str(device.get("platform_name") or "")
            if device.get("product_type_desc") == "Mobile" or platform in ("Android", "iOS"):
                skipped_mobile = skipped_mobile + 1
                continue
            active = (
                device.get("status") == "normal"
                and not is_rfm(device.get("reduced_functionality_mode"))
                and bool(device.get("agent_version"))
                and bool(device.get("last_seen"))
            )
            if not active:
                skipped_inactive = skipped_inactive + 1
                continue
            judged = judged + 1
            policies = device.get("device_policies") if isinstance(device.get("device_policies"), dict) else {}
            sensor_update = policies.get("sensor_update")
            mode = update_mode(sensor_update)
            counts[mode] = counts[mode] + 1
            if mode == "auto" and str(sensor_update.get("applied")).strip().lower() != "true":
                pending = pending + 1
        if counts["unknown"]:
            api_errors.append(
                f"{counts['unknown']} host(s) report a sensor-update settings_hash in a shape this check does not "
                "recognise; not evaluated rather than guessed"
            )

    not_auto = counts["pinned"] + counts["off"] + counts["none"]
    result_value = not api_errors and judged > 0 and not_auto == 0

    pass_reasons = []
    fail_reasons = []
    recommendations = []
    if api_errors:
        fail_reasons.append("Not measured: " + "; ".join(api_errors))
        recommendations.append(
            "Verify the CrowdStrike API credentials (Hosts: Read) and that the device method pages through the "
            "whole estate, then re-run the scan."
        )
    elif judged == 0:
        fail_reasons.append(
            f"No active Falcon sensor was returned ({len(resources)} host records, {skipped_mobile} mobile, "
            f"{skipped_inactive} inactive); automatic sensor updates cannot be shown."
        )
        recommendations.append("Confirm Falcon sensors are deployed and reporting, then re-run the scan.")
    elif result_value:
        pass_reasons.append(
            f"All {judged} active Falcon sensors have a sensor-update policy that tracks a tagged CrowdStrike release "
            f"(automatic sensor updates on){'; ' + str(pending) + ' have a newer policy revision pending' if pending else ''}."
        )
    else:
        fail_reasons.append(
            f"{not_auto} of {judged} active Falcon sensors do not update automatically: {counts['off']} on a policy "
            f"with sensor version updates off, {counts['pinned']} pinned to a fixed build, {counts['none']} with no "
            "sensor-update policy applied."
        )
        recommendations.append(
            "Set the sensor-update policy for those hosts' groups to an automatic build (N-1 or N-2) in the Falcon console."
        )

    summary = {
        "hostRecords": len(resources),
        "activeSensorsJudged": judged,
        "automaticUpdates": counts["auto"],
        "updatesOff": counts["off"],
        "pinnedBuild": counts["pinned"],
        "noSensorUpdatePolicy": counts["none"],
        "unrecognisedSettings": counts["unknown"],
        "policyRevisionPending": pending,
        "mobileSkipped": skipped_mobile,
        "inactiveSkipped": skipped_inactive,
    }
    result = {
        "isPatchManagementEnabled": bool(result_value),
        "activeSensorsJudged": judged,
        "sensorsWithoutAutomaticUpdates": not_auto,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=summary,
        metadata={
            "transformationId": "isPatchManagementEnabled",
            "vendor": "CrowdStrike Falcon",
            "category": "epp",
            "source": "devices/combined/devices/v1 device_policies.sensor_update",
        },
        api_errors=api_errors,
    )
