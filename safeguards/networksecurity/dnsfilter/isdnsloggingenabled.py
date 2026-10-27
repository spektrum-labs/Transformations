"""
Transformation: isDNSLoggingEnabled
Vendor: DNSFilter
Category: Network Security / DNS Logging

Validates that DNS query logging is enabled for audit and threat analysis.

Reads GET /v1/traffic_reports/total_requests (Integration-Service method getQueryLogs,
windowed to the last 7 days). DNSFilter has no logging on/off switch and keeps query
logs for 9 days, so the measured fact is whether the organisation produced DNS traffic
in the window: the sum of values[].total over the report's day buckets. The vendor body
is {"data": {"organization_ids": [...], "values": [{"bucket": ..., "total": N, ...}]}};
Token-Service strips the `data` wrapper before validating and calling transform
(codeexecutor._parse_api_response_for_transformer navigates response/result/apiResponse/
Output/data), so `values` is read at the top level and, for a raw body, under `data`.
A body with no report, no buckets, or zero traffic next to buckets that carry no numeric
total is not measured: the criterion is None with a dataCollection error, never a False.

Runs in Token-Service's RestrictedPython sandbox: no map(), no names starting with `_`,
no `__name__`; the file is fetched by URL and must stay self-contained.
"""

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
                if key in data and isinstance(data.get(key), dict):
                    data = data[key]
                    unwrapped = True
                    break
            if not unwrapped:
                break
    return data, {"status": "unknown", "errors": [], "warnings": ["Legacy input format"]}


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, transformation_errors=None, api_errors=None, additional_findings=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {
                "status": "error" if (api_errors or []) else "success",
                "errors": api_errors or []
            },
            "validation": {
                "status": validation.get("status", "unknown"),
                "errors": validation.get("errors", []),
                "warnings": validation.get("warnings", [])
            },
            "transformation": {
                "status": "error" if (transformation_errors or []) else "success",
                "errors": transformation_errors or [],
                "inputSummary": input_summary or {}
            },
            "evaluation": {
                "passReasons": pass_reasons or [],
                "failReasons": fail_reasons or [],
                "recommendations": recommendations or [],
                "additionalFindings": additional_findings or []
            },
            "metadata": {
                "evaluatedAt": datetime.utcnow().isoformat() + "Z",
                "schemaVersion": "1.0",
                "transformationId": "isDNSLoggingEnabled",
                "vendor": "DNSFilter",
                "category": "Network Security"
            }
        }
    }


def report_of(data):
    """The report dict that carries `values`: the body itself, or its `data` for a raw vendor body."""
    if not isinstance(data, dict):
        return None
    if isinstance(data.get("values"), list):
        return data
    inner = data.get("data")
    if isinstance(inner, dict) and isinstance(inner.get("values"), list):
        return inner
    return None


def kind_of(value):
    """A plain word for a value's type, for diagnostics (bool before int: True is an int)."""
    for kind, name in ((bool, "boolean"), (dict, "object"), (list, "list"), (str, "string"), (int, "number"),
                       (float, "number")):
        if isinstance(value, kind):
            return name
    return "null" if value is None else "unknown"


def body_keys(data):
    """The first ten keys of a body, for diagnostics."""
    return ", ".join(sorted(str(k) for k in data)[:10])


def why_unreadable(data):
    if not isinstance(data, dict):
        return f"body is {kind_of(data)}, not an object"
    if not data:
        return "body is empty"
    status = data.get("status_code") or data.get("statusCode") or data.get("status")
    http = ""
    if str(status).isdigit() and str(status) != "0":
        http = f" (HTTP {status})"
    elif status:
        http = f" (status={status})"
    for key in ("error", "errors"):
        if key in data:
            return f"vendor error{http}: {str(data[key])[:200]}"
    if "message" in data:
        return f"vendor message{http} and no report: {str(data['message'])[:200]}"
    if "values" not in data and "data" not in data:
        return f"body is not a traffic report (keys: {body_keys(data)})"
    return "`values` is missing or is not a list of report buckets"


def bucket_total(bucket):
    """A bucket's `total` as a non-negative whole number, or None when it is missing, null, a string,
    a bool, negative, fractional or not finite (the vendor types it as an integer count)."""
    total = bucket.get("total") if isinstance(bucket, dict) else None
    if isinstance(total, bool) or not isinstance(total, (int, float)):
        return None
    if isinstance(total, float) and (total != total or total in (float("inf"), float("-inf")) or total != int(total)):
        return None
    return None if total < 0 else int(total)


def transform(input):
    criteriaKey = "isDNSLoggingEnabled"

    def not_measured(reason, recommendation=None, input_summary=None, transformation_errors=None):
        return create_response(
            result={criteriaKey: None, "totalQueries": None},
            validation=validation,
            api_errors=[reason],
            fail_reasons=["DNS query volume could not be measured"],
            recommendations=[recommendation] if recommendation else [],
            input_summary=input_summary,
            transformation_errors=transformation_errors
        )

    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        if validation.get("status") == "failed":
            errors = validation.get("errors", []) or ["schema rejected the body"]
            return not_measured("Input validation failed: " + "; ".join(str(e) for e in errors))

        report = report_of(data)
        if report is None:
            return not_measured(
                f"DNSFilter did not return a total_requests traffic report: {why_unreadable(data)}",
                "Re-run the check; if it persists, confirm the DNSFilter API key can read traffic reports",
                {"bodyKeys": body_keys(data)} if isinstance(data, dict) else {}
            )

        values = report["values"]
        totals = [t for t in (bucket_total(v) for v in values) if t is not None]
        unmeasured = len(values) - len(totals)
        total_queries = sum(totals)
        logging_enabled = total_queries > 0
        if not logging_enabled and (not values or unmeasured):
            # No traffic seen, but the window was not fully read: no buckets came back, or some carry
            # no numeric `total`. That cannot say "no DNS logs"; it says the report was not measured.
            why = ("the report returned no buckets for the window" if not values
                   else f"{unmeasured} of {len(values)} report bucket(s) carry no numeric `total`")
            return not_measured(
                f"DNSFilter total_requests report could not be measured: {why}",
                "Re-run the check; if it persists, confirm the organisation has networks or roaming clients and that the DNSFilter report format is unchanged",
                {"buckets": len(values), "unmeasuredBuckets": unmeasured, "bodyKeys": body_keys(report)}
            )
        return create_response(
            result={criteriaKey: logging_enabled, "totalQueries": total_queries},
            validation=validation,
            pass_reasons=[f"DNSFilter recorded {total_queries} DNS queries in the report window; query logs are retained"] if logging_enabled else [],
            fail_reasons=[] if logging_enabled else ["DNSFilter recorded no DNS queries in the report window, so there is nothing in the query log"],
            recommendations=[] if logging_enabled else ["Confirm DNSFilter networks or roaming clients are deployed and resolving through DNSFilter; query logs are kept automatically once traffic flows"],
            additional_findings=[f"{unmeasured} of {len(values)} report bucket(s) carry no numeric `total` and were not counted"] if unmeasured else [],
            input_summary={"totalQueries": total_queries, "buckets": len(values), "unmeasuredBuckets": unmeasured}
        )

    except Exception as e:
        validation = {"status": "error", "errors": [], "warnings": []}
        return not_measured(f"Transformation error: {str(e)}", transformation_errors=[str(e)])
