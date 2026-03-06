"""
Transformation: isDNSLoggingEnabled
Vendor: DNSFilter
Category: Network Security / DNS Logging

Validates that DNS query logging is enabled for audit and threat analysis.
Checks the total_queries traffic report endpoint for query log data.
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
                result={criteriaKey: False},
                validation=validation,
                fail_reasons=["Input validation failed"]
            )

        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []

        logging_enabled = False
        total_queries = 0

        if isinstance(data, dict):
            # Check for total query count in traffic report
            total_queries = data.get('total_queries', data.get('totalQueries',
                           data.get('total', data.get('count', 0))))

            # Check for query log entries
            queries = data.get('queries', data.get('data', data.get('logs', [])))
            if isinstance(queries, list) and len(queries) > 0:
                logging_enabled = True
                total_queries = total_queries or len(queries)

            # A positive query count indicates logging is active
            if isinstance(total_queries, (int, float)) and total_queries > 0:
                logging_enabled = True

            # Check for explicit logging configuration flags
            logging_config = data.get('logging_enabled', data.get('loggingEnabled',
                            data.get('query_logging', data.get('queryLogging', None))))
            if logging_config is not None:
                logging_enabled = bool(logging_config)

        elif isinstance(data, list) and len(data) > 0:
            # Direct list of query logs
            logging_enabled = True
            total_queries = len(data)

        if logging_enabled:
            reason = "DNS query logging is enabled"
            if total_queries > 0:
                reason += f" ({total_queries} queries recorded)"
            pass_reasons.append(reason)
        else:
            fail_reasons.append("DNS query logging does not appear to be enabled")
            recommendations.append("Enable DNS query logging in DNSFilter for audit and threat analysis")

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
                "totalQueries": total_queries
            }
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
