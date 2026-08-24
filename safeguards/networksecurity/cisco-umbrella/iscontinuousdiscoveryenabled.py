import json
from datetime import datetime, timedelta


def extract_input(input_data):
    """Extract (data, validation) from either the enriched or the legacy input format."""
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for attempt in range(3):
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
    """Build the standard 5-section transformation response."""
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    api_err_list = api_errors or []
    transform_err_list = transformation_errors or []
    response_metadata = {
        "evaluatedAt": datetime.utcnow().isoformat() + "Z",
        "schemaVersion": "2.0",
        "vendor": "Cisco Umbrella",
        "category": "Network Security",
    }
    if metadata:
        response_metadata.update(metadata)
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error" if api_err_list else "success", "errors": api_err_list},
            "validation": {
                "status": validation.get("status", "unknown"),
                "errors": validation.get("errors", []),
                "warnings": validation.get("warnings", []),
            },
            "transformation": {
                "status": "error" if transform_err_list else "success",
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


def as_list(data, item_key="items"):
    """Return the list of records regardless of how far the platform unwrapped the response.

    Token-Service walks response/result/apiResponse/Output/data before the transform runs,
    so a {"data": [...]} envelope can arrive already reduced to a bare list.
    """
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for key in (item_key, "items", "data", "records"):
            value = data.get(key)
            if isinstance(value, list):
                return value
    return []


CRITERIA_KEY = "isContinuousDiscoveryEnabled"

# App Discovery must have observed an app within this many days for the feed to
# count as live rather than a stale one-off export.
MAX_DETECTION_AGE_DAYS = 30


def parse_timestamp(value):
    """Parse Umbrella's ISO-8601 timestamps, tolerating a trailing Z and missing time.

    Deliberately avoids datetime.strptime: it lazily imports the private _strptime
    module on first call, which the transformation sandbox blocks, so strptime works
    locally and raises ImportError in production. fromisoformat is implemented in C
    and needs no import. The offset is stripped so the result stays naive, matching
    datetime.utcnow() - comparing aware and naive datetimes raises TypeError.
    """
    if not value:
        return None
    text = str(value).strip()
    if text.endswith("Z"):
        text = text[:-1]
    if "+" in text:
        text = text.split("+")[0]
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        return None


def transform(input):
    try:
        if isinstance(input, (str, bytes)):
            input = json.loads(input)
        data, validation = extract_input(input)
        apps = as_list(data)
        apps = [a for a in apps if isinstance(a, dict)]

        # itemsCount is the fleet-wide total for the query; len(apps) is only this page.
        total_discovered = None
        if isinstance(data, dict) and isinstance(data.get("itemsCount"), int):
            total_discovered = data["itemsCount"]
        if total_discovered is None:
            total_discovered = len(apps)

        detections = []
        for app in apps:
            stamp = parse_timestamp(app.get("lastDetected"))
            if stamp is not None:
                detections.append(stamp)

        latest = max(detections) if detections else None
        now = datetime.utcnow()
        age_days = (now - latest).days if latest else None
        fresh = age_days is not None and age_days <= MAX_DETECTION_AGE_DAYS
        enabled = total_discovered > 0 and fresh

        result = {
            CRITERIA_KEY: enabled,
            "discoveredApplications": total_discovered,
            "applicationsOnPage": len(apps),
            "applicationsWithDetectionDates": len(detections),
            "latestDetection": latest.isoformat() if latest else None,
            "latestDetectionAgeDays": age_days,
            "maxDetectionAgeDays": MAX_DETECTION_AGE_DAYS,
        }

        pass_reasons, fail_reasons, recommendations = [], [], []
        if total_discovered == 0:
            fail_reasons.append(
                "App Discovery returned no applications, so continuous cloud-app discovery "
                "cannot be confirmed as running.")
            recommendations.append(
                "Confirm App Discovery is enabled and that DNS or SWG traffic is reaching "
                "Umbrella from managed identities.")
        elif not detections:
            fail_reasons.append(
                "%d application(s) were discovered but none carry a lastDetected timestamp, "
                "so the feed cannot be shown to be updating." % total_discovered)
        elif enabled:
            pass_reasons.append(
                "%d application(s) discovered, most recently %d day(s) ago (%s), confirming "
                "App Discovery is continuously surfacing cloud apps from live traffic rather "
                "than a one-off scan."
                % (total_discovered, age_days, latest.date().isoformat()))
        else:
            fail_reasons.append(
                "The most recent app detection is %d day(s) old (%s), beyond the %d-day "
                "freshness bar, so the discovery feed appears stale."
                % (age_days, latest.date().isoformat(), MAX_DETECTION_AGE_DAYS))
            recommendations.append(
                "Investigate why Umbrella has not observed new cloud-app activity recently; "
                "check that identities are still forwarding DNS/SWG traffic.")

        return create_response(
            result=result, validation=validation,
            pass_reasons=pass_reasons, fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={"discoveredApplications": total_discovered,
                           "latestDetectionAgeDays": age_days},
            metadata={"transformationId": CRITERIA_KEY})
    except Exception as e:
        return create_response(
            result={CRITERIA_KEY: False}, transformation_errors=[str(e)],
            fail_reasons=["Transformation error: %s" % e],
            metadata={"transformationId": CRITERIA_KEY})
