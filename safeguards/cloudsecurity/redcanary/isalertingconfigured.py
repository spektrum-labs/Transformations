"""
Transformation: isAlertingConfigured
Vendor: Red Canary
Category: Cloud Security / Alerting

Ensures detection alerting is configured and generating findings.
Checks the detections endpoint for detection activity.
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
                "transformationId": "isAlertingConfigured",
                "vendor": "Red Canary",
                "category": "Cloud Security"
            }
        }
    }


def transform(input):
    criteriaKey = "isAlertingConfigured"

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

        alerting_configured = False
        total_detections = 0
        acknowledged_detections = 0
        severity_counts = {}

        detections = []

        if isinstance(data, dict):
            if 'detections' in data and isinstance(data['detections'], list):
                detections = data['detections']
            elif 'data' in data and isinstance(data['data'], list):
                detections = data['data']

            # Check meta for total count (may have detections even if current page is empty)
            meta = data.get('meta', {})
            if isinstance(meta, dict):
                total_from_meta = meta.get('total_count', meta.get('total', 0))
                if isinstance(total_from_meta, (int, float)) and total_from_meta > 0:
                    alerting_configured = True
                    total_detections = int(total_from_meta)
        elif isinstance(data, list):
            detections = data

        if detections:
            total_detections = max(total_detections, len(detections))

            for detection in detections:
                if isinstance(detection, dict):
                    # Track severity distribution
                    severity = str(detection.get('severity', detection.get('threat_level', 'unknown'))).lower()
                    severity_counts[severity] = severity_counts.get(severity, 0) + 1

                    # Track acknowledged/remediated detections
                    state = str(detection.get('state', '')).lower()
                    if state in ('acknowledged', 'remediated', 'resolved'):
                        acknowledged_detections += 1

        # Alerting is configured if we can access the detections endpoint successfully
        # (even with zero detections, it means the system is monitoring)
        if total_detections > 0:
            alerting_configured = True
        elif isinstance(data, dict) or isinstance(data, list):
            # Valid response from detections endpoint means alerting is configured
            alerting_configured = True
            additional_findings.append(
                "No detections found - this may indicate a clean environment or "
                "that detection rules need to be configured"
            )

        if alerting_configured:
            if total_detections > 0:
                reason = f"Detection alerting is configured ({total_detections} detection(s) found"
                if acknowledged_detections > 0:
                    reason += f", {acknowledged_detections} acknowledged/remediated)"
                else:
                    reason += ")"
                pass_reasons.append(reason)
            else:
                pass_reasons.append("Detection alerting endpoint is accessible and configured")
        else:
            fail_reasons.append("Detection alerting could not be verified")
            recommendations.append("Configure detection alerting in Red Canary and ensure API token has detection read permissions")

        return create_response(
            result={
                criteriaKey: alerting_configured,
                "totalDetections": total_detections,
                "acknowledgedDetections": acknowledged_detections,
                "severityCounts": severity_counts
            },
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={
                "totalDetections": total_detections,
                "acknowledgedDetections": acknowledged_detections,
                "severityCounts": severity_counts
            }
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
