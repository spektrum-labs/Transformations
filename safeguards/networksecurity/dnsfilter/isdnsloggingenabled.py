"""
Transformation: isDNSLoggingEnabled
Vendor: DNSFilter
Category: Network Security / DNS Logging

Validates that DNS query logging is enabled for audit and threat analysis.

Reads GET /v1/traffic_reports/total_requests (the Integration-Service method
getQueryLogs, windowed to the last 7 days). DNSFilter has no logging on/off
switch and keeps query logs for 9 days, so the measured fact is whether the
organisation produced DNS traffic in the window. The vendor body is
{"data": {"organization_ids": [...], "values": [{"bucket": ..., "total": N, ...}]}};
Token-Service strips the `data` wrapper before calling transform (codeexecutor
_parse_api_response_for_transformer navigates response/result/apiResponse/Output/data),
so the transform reads `values` at the top level and, for a raw body, under `data`.
The query count is the sum of values[].total. A body without that report (error
envelope, empty, unrelated) is not measured: the criterion is None with a
dataCollection error, never a False.
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


def report_values(data):
    """The `values` bucket list of a total_requests report, or None when the body is not one.

    Token-Service hands the transform the report with its `data` wrapper already removed, so
    `values` is normally at the top level; a raw vendor body still carries it under `data`."""
    if not isinstance(data, dict):
        return None
    values = data.get("values")
    if values is None and isinstance(data.get("data"), dict):
        values = data["data"].get("values")
    return values if isinstance(values, list) else None


def kind_of(value):
    """A plain word for a value's type; the sandbox forbids `__name__`."""
    for kind, name in ((dict, "object"), (list, "list"), (str, "string"), (bool, "boolean"),
                       (int, "number"), (float, "number")):
        if isinstance(value, kind):
            return name
    return "null" if value is None else "unknown"


def why_unreadable(data):
    if not isinstance(data, dict):
        return f"body is {kind_of(data)}, not an object"
    if not data:
        return "body is empty"
    for key in ("error", "errors", "message"):
        if key in data:
            detail = data[key]
            status = data.get("status_code") or data.get("statusCode") or data.get("status")
            return f"vendor error{f' (HTTP {status})' if status else ''}: {str(detail)[:200]}"
    if "values" not in data and "data" not in data:
        return "body is not a traffic report (keys: " + ", ".join(sorted(map(str, data))[:10]) + ")"
    return "`values` is missing or is not a list of report buckets"


def transform(input):
    criteriaKey = "isDNSLoggingEnabled"

    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        if validation.get("status") == "failed":
            return create_response(
                result={criteriaKey: None, "totalQueries": None},
                validation=validation,
                api_errors=["Input validation failed: " + "; ".join(str(e) for e in validation.get("errors", []) or ["schema rejected the body"])],
                fail_reasons=["Input validation failed"]
            )

        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []

        values = report_values(data)
        if values is None:
            why = why_unreadable(data)
            return create_response(
                result={criteriaKey: None, "totalQueries": None},
                validation=validation,
                api_errors=[f"DNSFilter did not return a total_requests traffic report: {why}"],
                fail_reasons=["DNS query volume could not be measured"],
                recommendations=["Re-run the check; if it persists, confirm the DNSFilter API key can read traffic reports"],
                input_summary={"bodyKeys": sorted(data)[:10] if isinstance(data, dict) else kind_of(data)}
            )

        total_queries = sum(
            v["total"] for v in values
            if isinstance(v, dict) and isinstance(v.get("total"), (int, float)) and not isinstance(v.get("total"), bool)
        )
        total_queries = int(total_queries)
        logging_enabled = total_queries > 0

        if logging_enabled:
            pass_reasons.append(f"DNSFilter recorded {total_queries} DNS queries in the report window; query logs are retained")
        else:
            fail_reasons.append("DNSFilter recorded no DNS queries in the report window, so there is nothing in the query log")
            recommendations.append("Confirm DNSFilter networks or roaming clients are deployed and resolving through DNSFilter; query logs are kept automatically once traffic flows")

        return create_response(
            result={
                criteriaKey: logging_enabled,
                "totalQueries": total_queries
            },
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={
                "totalQueries": total_queries,
                "buckets": len(values)
            }
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: None, "totalQueries": None},
            validation={"status": "error", "errors": [], "warnings": []},
            api_errors=[f"Transformation error: {str(e)}"],
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
