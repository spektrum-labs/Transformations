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


def parse_iso_ts(ts):
    if not isinstance(ts, str) or not ts:
        return None
    try:
        if "T" not in ts:
            return None
        date_part, time_part = ts.split("T", 1)
        year, month, day = date_part.split("-")
        time_part = time_part.rstrip("Z")
        if "." in time_part:
            hms = time_part.split(".")[0]
        else:
            hms = time_part
        parts = hms.split(":")
        if len(parts) < 3:
            return None
        h, m, s = parts[0], parts[1], parts[2]
        return datetime(int(year), int(month), int(day), int(h), int(m), int(s))
    except Exception:
        return None


def transform(input):
    data, validation = extract_input(input)
    data = data if isinstance(data, (dict, list)) else {}

    if isinstance(data, list):
        assets = data
    elif isinstance(data, dict):
        assets = data.get("assets") or []
    else:
        assets = []

    total_reported = data.get("total") if isinstance(data, dict) else None
    total = total_reported if isinstance(total_reported, int) and total_reported > 0 else len(assets)

    now = datetime.utcnow()
    recent_window_days = 7

    parsed_count = 0
    recent_count = 0
    sample_timestamps = []

    for asset in assets:
        if not isinstance(asset, dict):
            continue
        ts = asset.get("bd.last_metadata_change")
        parsed = parse_iso_ts(ts)
        if parsed is None:
            continue
        parsed_count = parsed_count + 1
        if len(sample_timestamps) < 3:
            sample_timestamps.append(ts)
        diff_days = (now - parsed).total_seconds() / 86400.0
        if diff_days <= recent_window_days and diff_days >= -1:
            recent_count = recent_count + 1

    recent_ratio = (recent_count / parsed_count) if parsed_count > 0 else 0.0

    is_continuous = parsed_count > 0 and recent_ratio >= 0.5

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if parsed_count == 0:
        fail_reasons.append(
            "No assets in the inventory response (total=%s, sampled=%s) carry a parseable bd.last_metadata_change timestamp, so continuous re-scanning activity cannot be confirmed." % (total, len(assets))
        )
        recommendations.append(
            "Verify the ASM inventory API is populated and that bd.last_metadata_change is included and populated on asset records to evidence ongoing re-discovery."
        )
    elif is_continuous:
        pass_reasons.append(
            "%d of %d sampled assets (%.0f%%) with a parseable bd.last_metadata_change report a metadata update within the last %d days (sample timestamps: %s), evidencing continuous re-discovery rather than a one-time scan."
            % (recent_count, parsed_count, recent_ratio * 100.0, recent_window_days, sample_timestamps)
        )
    else:
        fail_reasons.append(
            "Only %d of %d sampled assets (%.0f%%) with a parseable bd.last_metadata_change report a metadata update within the last %d days (sample timestamps: %s); this falls below the 50%% recency threshold expected for continuous discovery."
            % (recent_count, parsed_count, recent_ratio * 100.0, recent_window_days, sample_timestamps)
        )
        recommendations.append(
            "Confirm ASM continuous discovery/re-scanning schedules are active on this account; assets should show bd.last_metadata_change updates on a rolling basis, not a static one-time snapshot."
        )

    result = {
        "isContinuousDiscoveryEnabled": is_continuous,
        "totalAssets": total,
        "assetsSampled": len(assets),
        "assetsWithTimestamp": parsed_count,
        "assetsRecentlyUpdated": recent_count,
    }

    input_summary = {
        "totalAssets": total,
        "assetsSampled": len(assets),
        "assetsWithParseableTimestamp": parsed_count,
        "recentWindowDays": recent_window_days,
        "recentRatio": recent_ratio,
    }

    metadata = {
        "transformationId": "isContinuousDiscoveryEnabled",
        "vendor": "Tenable Attack Surface Management",
        "category": "asm",
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata=metadata,
    )
