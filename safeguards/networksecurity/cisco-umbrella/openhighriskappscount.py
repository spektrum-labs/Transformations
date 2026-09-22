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


CRITERIA_KEY = "openHighRiskAppsCount"

# Umbrella's weightedRisk ladder is veryLow|low|medium|high|veryHigh.
# NOTE the camelCase: filtering on the string "very high" silently misses every
# veryHigh app, which is exactly how an earlier draft of this check under-reported.
HIGH_RISK = ("high", "veryhigh")
# An app is "open" while nobody has made a decision on it. approved / notApproved
# both represent a completed review, so neither counts as open.
OPEN_LABEL = "unreviewed"
# Returned when the vendor gave us nothing to count. Deliberately non-zero so an
# API failure can never satisfy the "0 open high-risk apps" pass condition.
UNDETERMINED = -1
# The App Discovery endpoint rejects relative from/to values and the platform has no
# date placeholder, so the URL cannot carry a window and the vendor applies its own
# (undocumented, and wider than 30 days). Bounding on lastDetected here makes the
# count depend on an explicit window rather than on that default.
MAX_DETECTION_AGE_DAYS = 30


def normalise(value):
    return str(value or "").strip().lower().replace(" ", "").replace("_", "")


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


def seen_recently(app, cutoff):
    """True when the app was observed inside the window (or carries no date at all)."""
    stamp = parse_timestamp(app.get("lastDetected"))
    if stamp is None:
        return True
    return stamp >= cutoff


def transform(input):
    try:
        if isinstance(input, (str, bytes)):
            input = json.loads(input)
        data, validation = extract_input(input)
        apps = as_list(data)
        apps = [a for a in apps if isinstance(a, dict)]

        total_pages = data.get("totalPages") if isinstance(data, dict) else None
        items_count = data.get("itemsCount") if isinstance(data, dict) else None

        # A count criterion whose pass value is 0 must never report 0 because the
        # call failed - that would score an outage as a clean bill of health. App
        # Discovery always answers with an envelope, so its absence means no data
        # was retrieved, and we return the UNDETERMINED sentinel instead.
        has_envelope = isinstance(data, dict) and (
            "items" in data or isinstance(data.get("itemsCount"), int))
        if not has_envelope:
            return create_response(
                result={CRITERIA_KEY: UNDETERMINED},
                validation=validation,
                api_errors=["App Discovery returned no recognisable response envelope."],
                fail_reasons=[
                    "Could not retrieve discovered applications from Umbrella, so the number "
                    "of open high-risk apps is unknown. Reporting this as unknown rather than "
                    "zero, because zero is the passing value for this check."],
                recommendations=[
                    "Check Umbrella API availability and that the API key retains the "
                    "reports.appdiscovery scope."],
                input_summary={"applicationsReturned": 0},
                metadata={"transformationId": CRITERIA_KEY})

        cutoff = datetime.utcnow() - timedelta(days=MAX_DETECTION_AGE_DAYS)
        all_high_risk = [a for a in apps if normalise(a.get("weightedRisk")) in HIGH_RISK]
        high_risk = [a for a in all_high_risk if seen_recently(a, cutoff)]
        stale_excluded = len(all_high_risk) - len(high_risk)
        open_apps = [a for a in high_risk if normalise(a.get("label")) == OPEN_LABEL]
        reviewed = len(high_risk) - len(open_apps)

        count = len(open_apps)
        # Honest truncation reporting: if the vendor says there are more pages than we
        # were given, the count is a floor rather than an exact figure.
        truncated = bool(isinstance(total_pages, int) and total_pages > 1)

        result = {
            CRITERIA_KEY: count,
            "highRiskApplications": len(high_risk),
            "reviewedHighRiskApplications": reviewed,
            "applicationsReturned": len(apps),
            "vendorReportedTotal": items_count,
            "highRiskOutsideWindow": stale_excluded,
            "detectionWindowDays": MAX_DETECTION_AGE_DAYS,
            "truncated": truncated,
        }

        pass_reasons, fail_reasons, recommendations = [], [], []
        if count == 0:
            if not high_risk:
                pass_reasons.append(
                    "Umbrella App Discovery reports no high or veryHigh risk cloud "
                    "applications, so there is no open shadow-IT exposure to review.")
            else:
                pass_reasons.append(
                    "All %d high/veryHigh risk application(s) have been reviewed, leaving "
                    "no open high-risk shadow IT." % len(high_risk))
        else:
            very_high = [a for a in open_apps if normalise(a.get("weightedRisk")) == "veryhigh"]
            fail_reasons.append(
                "%d high-risk cloud application(s) discovered by Umbrella remain unreviewed "
                "(%d of them veryHigh risk), representing live shadow-IT exposure with no "
                "compensating decision recorded." % (count, len(very_high)))
            names = [a.get("name") for a in (very_high + open_apps)[:8] if a.get("name")]
            if names:
                fail_reasons.append("Examples: %s" % ", ".join(names))
            recommendations.append(
                "Review the high-risk applications in Umbrella under Reports > App Discovery "
                "and either approve or block each one so none remain unreviewed.")

        findings = []
        if stale_excluded:
            findings.append(
                "%d high-risk app(s) were last seen more than %d days ago and were excluded "
                "as historical rather than live exposure."
                % (stale_excluded, MAX_DETECTION_AGE_DAYS))
        if truncated:
            findings.append(
                "Vendor reported %s page(s) of results but only the first was read; the count "
                "above is a floor, not an exact total." % total_pages)
        if isinstance(items_count, int) and items_count != len(apps):
            findings.append(
                "Vendor itemsCount is %d while %d record(s) were returned on this page."
                % (items_count, len(apps)))

        return create_response(
            result=result, validation=validation,
            pass_reasons=pass_reasons, fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={"openHighRiskAppsCount": count,
                           "highRiskApplications": len(high_risk)},
            additional_findings=findings,
            metadata={"transformationId": CRITERIA_KEY})
    except Exception as e:
        return create_response(
            result={CRITERIA_KEY: UNDETERMINED}, transformation_errors=[str(e)],
            fail_reasons=["Transformation error: %s" % e],
            metadata={"transformationId": CRITERIA_KEY})
