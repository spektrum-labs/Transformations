import json
from datetime import datetime, timedelta


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]

    data = input_data
    validation = {"status": "unknown", "errors": [], "warnings": ["Legacy input format"]}

    for _ in range(3):
        if not isinstance(data, dict):
            break
        unwrapped = False
        for key in ["api_response", "response", "result", "apiResponse", "Output"]:
            if key in data and isinstance(data.get(key), (dict, list)):
                data = data[key]
                unwrapped = True
                break
        if not unwrapped:
            break

    return data, validation


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, transformation_errors=None,
                    api_errors=None, additional_findings=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    if pass_reasons is None:
        pass_reasons = []
    if fail_reasons is None:
        fail_reasons = []
    if recommendations is None:
        recommendations = []
    if transformation_errors is None:
        transformation_errors = []
    if api_errors is None:
        api_errors = []
    if additional_findings is None:
        additional_findings = []
    if input_summary is None:
        input_summary = {}

    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {
                "status": "error" if api_errors else "success",
                "errors": api_errors
            },
            "validation": {
                "status": validation.get("status", "unknown"),
                "errors": validation.get("errors", []),
                "warnings": validation.get("warnings", [])
            },
            "transformation": {
                "status": "error" if transformation_errors else "success",
                "errors": transformation_errors,
                "inputSummary": input_summary
            },
            "evaluation": {
                "passReasons": pass_reasons,
                "failReasons": fail_reasons,
                "recommendations": recommendations,
                "additionalFindings": additional_findings
            },
            "metadata": {
                "evaluatedAt": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                "schemaVersion": "1.0",
                "transformationId": "isDeviceInventoryCurrent",
                "vendor": "Microsoft Intune",
                "category": "Asset Management"
            }
        }
    }


def transform(input):
    """
    Checks that enrolled devices have synced recently, indicating the device
    inventory is current and not stale.

    Evaluates lastSyncDateTime for each managed device. Returns true if >= 80%
    of devices have synced within the last 30 days.
    """
    criteriaKey = "isDeviceInventoryCurrent"
    STALE_THRESHOLD_DAYS = 30
    CURRENT_THRESHOLD_PERCENT = 80

    try:
        if isinstance(input, (str, bytes)):
            input = json.loads(input)

        data, validation = extract_input(input)

        if validation.get("status") == "failed":
            return create_response(
                result={criteriaKey: False},
                validation=validation,
                fail_reasons=["Input validation failed"]
            )

        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []

        devices = []
        if isinstance(data, list):
            devices = data
        elif isinstance(data, dict):
            devices = data.get("value", data.get("devices", []))
            if isinstance(devices, dict):
                devices = [devices]

        if not isinstance(devices, list):
            devices = []

        if len(devices) == 0:
            return create_response(
                result={criteriaKey: False},
                validation=validation,
                fail_reasons=["No managed devices found to evaluate"],
                recommendations=["Enroll devices into Intune to establish device inventory"]
            )

        now = datetime.utcnow()
        cutoff = now - timedelta(days=STALE_THRESHOLD_DAYS)
        current_count = 0
        stale_count = 0
        no_sync_count = 0

        for device in devices:
            if not isinstance(device, dict):
                continue
            last_sync = device.get("lastSyncDateTime", "")
            if not last_sync:
                no_sync_count += 1
                continue

            try:
                sync_dt = datetime.strptime(last_sync[:19], "%Y-%m-%dT%H:%M:%S")
                if sync_dt >= cutoff:
                    current_count += 1
                else:
                    stale_count += 1
            except (ValueError, TypeError):
                no_sync_count += 1

        total = len(devices)
        evaluable = current_count + stale_count
        current_pct = (current_count * 100 // total) if total > 0 else 0

        is_current = current_pct >= CURRENT_THRESHOLD_PERCENT

        if is_current:
            pass_reasons.append(
                "%d%% of devices (%d/%d) synced within the last %d days"
                % (current_pct, current_count, total, STALE_THRESHOLD_DAYS)
            )
        else:
            fail_reasons.append(
                "Only %d%% of devices (%d/%d) synced within the last %d days "
                "(threshold: %d%%)"
                % (current_pct, current_count, total, STALE_THRESHOLD_DAYS,
                   CURRENT_THRESHOLD_PERCENT)
            )
            recommendations.append(
                "Investigate stale devices that haven't synced in %d+ days. "
                "Consider retiring devices that are no longer active."
                % STALE_THRESHOLD_DAYS
            )

        if stale_count > 0:
            additional_findings.append(
                "%d device(s) have not synced in over %d days"
                % (stale_count, STALE_THRESHOLD_DAYS)
            )
        if no_sync_count > 0:
            additional_findings.append(
                "%d device(s) have no sync timestamp recorded" % no_sync_count
            )

        input_summary = {
            "totalDevices": total,
            "currentDevices": current_count,
            "staleDevices": stale_count,
            "noSyncDevices": no_sync_count,
            "currentPercentage": current_pct
        }

        return create_response(
            result={criteriaKey: is_current},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary=input_summary,
            additional_findings=additional_findings
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: %s" % str(e)]
        )
