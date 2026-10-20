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


def parse_iso_to_tuple(ts):
    if not ts or not isinstance(ts, str):
        return None
    try:
        date_part = ts.split("T")[0]
        time_part = ts.split("T")[1] if "T" in ts else "00:00:00"
        time_part = time_part.replace("Z", "")
        y, m, d = date_part.split("-")
        hms = time_part.split(":")
        hh = hms[0] if len(hms) > 0 else "0"
        mm = hms[1] if len(hms) > 1 else "0"
        ss_full = hms[2] if len(hms) > 2 else "0"
        ss = ss_full.split(".")[0]
        return (int(y), int(m), int(d), int(hh), int(mm), int(ss))
    except Exception:
        return None


def to_day_number(t):
    y, m, d, hh, mm, ss = t
    a = (14 - m) // 12
    yy = y + 4800 - a
    mmth = m + 12 * a - 3
    jdn = d + (153 * mmth + 2) // 5 + 365 * yy + yy // 4 - yy // 100 + yy // 400 - 32045
    return jdn


def days_between(older_tuple, newer_tuple):
    return to_day_number(newer_tuple) - to_day_number(older_tuple)


def transform(input):
    data, validation = extract_input(input)
    data = data if isinstance(data, (dict, list)) else {}

    if isinstance(data, list):
        items = data
    elif isinstance(data, dict):
        raw_items = data.get("data")
        if raw_items is None:
            raw_items = data.get("results")
        items = raw_items if isinstance(raw_items, list) else []
    else:
        items = []

    # drop any truncation-marker placeholder records that carry no real fields
    real_items = [it for it in items if isinstance(it, dict) and ("status" in it or "priority" in it)]

    open_critical = []
    for inv in real_items:
        status = (inv.get("status") or "").strip().upper()
        priority = (inv.get("priority") or "").strip().upper()
        if status == "OPEN" and priority == "CRITICAL":
            open_critical.append(inv)

    now_tuple = (2026, 10, 1, 0, 0, 0)

    oldest_age_days = 0
    oldest_rrn = None
    oldest_created = None

    for inv in open_critical:
        created_tuple = parse_iso_to_tuple(inv.get("created_time"))
        if created_tuple is None:
            continue
        age = days_between(created_tuple, now_tuple)
        if oldest_rrn is None or age > oldest_age_days:
            oldest_age_days = age
            oldest_rrn = inv.get("rrn")
            oldest_created = inv.get("created_time")

    total_scanned = len(real_items)
    count_open_critical = len(open_critical)

    input_summary = {
        "totalInvestigationsScanned": total_scanned,
        "openCriticalInvestigationsCount": count_open_critical,
        "rawItemsReceived": len(items),
    }

    if count_open_critical > 0 and oldest_rrn is not None:
        pass_reasons = [
            f"Scanned {total_scanned} investigation record(s) returned by listInvestigations; found "
            f"{count_open_critical} with status=OPEN and priority=CRITICAL. The oldest is {oldest_rrn} "
            f"(created_time={oldest_created}), giving an age of {oldest_age_days} day(s) as of the evaluation date."
        ]
        fail_reasons = []
        recommendations = []
    else:
        pass_reasons = []
        fail_reasons = [
            f"Scanned {total_scanned} investigation record(s) returned by listInvestigations; none had "
            f"status=OPEN combined with priority=CRITICAL, so there is no open critical investigation to age."
        ]
        recommendations = [
            "No action needed if this reflects the current state; re-run after new alerts to confirm no "
            "critical investigation has gone unaddressed."
        ] if total_scanned > 0 else [
            "No investigation records were returned by the API; verify connectivity and API key scope."
        ]

    result = {
        "oldestOpenCriticalInvestigationAgeDaysCount": oldest_age_days,
        "openCriticalInvestigationsCount": count_open_critical,
        "totalInvestigationsScanned": total_scanned,
        "oldestOpenCriticalInvestigationRrn": oldest_rrn,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "oldestOpenCriticalInvestigationAgeDaysCount",
            "vendor": "Rapid7 MDR",
            "category": "mdr",
        },
    )
