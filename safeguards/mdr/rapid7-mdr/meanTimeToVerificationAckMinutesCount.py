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


def parse_iso_timestamp(ts):
    """Parse an ISO8601 timestamp like 2026-09-30T21:13:29.182Z into epoch seconds, without strptime."""
    if not ts or not isinstance(ts, str):
        return None
    try:
        s = ts.strip()
        if s.endswith("Z"):
            s = s[:-1]
        if "T" not in s:
            return None
        date_part, time_part = s.split("T", 1)
        year_s, month_s, day_s = date_part.split("-")
        year = int(year_s)
        month = int(month_s)
        day = int(day_s)
        hour = 0
        minute = 0
        second = 0.0
        if time_part:
            hms = time_part.split(":")
            if len(hms) >= 1 and hms[0]:
                hour = int(hms[0])
            if len(hms) >= 2 and hms[1]:
                minute = int(hms[1])
            if len(hms) >= 3 and hms[2]:
                second = float(hms[2])
        days_before_month = [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334]

        def is_leap(y):
            return (y % 4 == 0 and y % 100 != 0) or (y % 400 == 0)

        def days_from_civil(y, m, d):
            total_days = 0
            if y >= 1970:
                for yy in range(1970, y):
                    total_days = total_days + (366 if is_leap(yy) else 365)
            else:
                for yy in range(y, 1970):
                    total_days = total_days - (366 if is_leap(yy) else 365)
            total_days = total_days + days_before_month[m - 1]
            if m > 2 and is_leap(y):
                total_days = total_days + 1
            total_days = total_days + (d - 1)
            return total_days

        total_days = days_from_civil(year, month, day)
        epoch_seconds = total_days * 86400 + hour * 3600 + minute * 60 + second
        return epoch_seconds
    except Exception:
        return None


def transform(input):
    data, validation = extract_input(input)
    data = data if isinstance(data, (dict, list)) else {}

    if isinstance(data, list):
        items = data
    elif isinstance(data, dict):
        items = data.get("data") or []
        if not isinstance(items, list):
            items = []
    else:
        items = []

    gaps_minutes = []
    considered = 0
    skipped_no_assignee = 0
    skipped_bad_time = 0

    for inv in items:
        if not isinstance(inv, dict):
            continue
        assignee = inv.get("assignee")
        if not assignee:
            skipped_no_assignee = skipped_no_assignee + 1
            continue
        considered = considered + 1
        created_ts = parse_iso_timestamp(inv.get("created_time"))
        ack_ts = parse_iso_timestamp(inv.get("last_accessed"))
        if created_ts is None or ack_ts is None:
            skipped_bad_time = skipped_bad_time + 1
            continue
        delta_minutes = (ack_ts - created_ts) / 60.0
        if delta_minutes < 0:
            delta_minutes = 0.0
        gaps_minutes.append(delta_minutes)

    total_investigations = len(items)

    if gaps_minutes:
        mean_minutes = sum(gaps_minutes) / len(gaps_minutes)
        mean_minutes_int = int(round(mean_minutes))
    else:
        mean_minutes_int = 0

    input_summary = {
        "totalInvestigations": total_investigations,
        "investigationsWithAssignee": considered,
        "investigationsUsedForMean": len(gaps_minutes),
        "skippedNoAssignee": skipped_no_assignee,
        "skippedBadTimestamp": skipped_bad_time,
    }

    if gaps_minutes:
        pass_reasons = [
            f"Computed mean time-to-verification-acknowledgement across {len(gaps_minutes)} assigned investigations "
            f"(of {total_investigations} total fetched), using last_accessed minus created_time as the acknowledgement proxy. "
            f"Mean gap = {mean_minutes_int} minutes."
        ]
        fail_reasons = []
        recommendations = []
    else:
        pass_reasons = []
        fail_reasons = [
            f"No investigations with a populated assignee and parseable created_time/last_accessed were found among "
            f"{total_investigations} fetched investigations (skipped_no_assignee={skipped_no_assignee}, "
            f"skipped_bad_timestamp={skipped_bad_time}); mean acknowledgement time could not be computed."
        ]
        recommendations = [
            "Ensure investigations are being assigned to analysts so acknowledgement latency can be measured."
        ]

    result = {
        "meanTimeToVerificationAckMinutesCount": mean_minutes_int,
        "investigationsUsedForMean": len(gaps_minutes),
        "totalInvestigations": total_investigations,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "meanTimeToVerificationAckMinutesCount",
            "vendor": "Rapid7 MDR",
            "category": "MDR",
        },
    )
