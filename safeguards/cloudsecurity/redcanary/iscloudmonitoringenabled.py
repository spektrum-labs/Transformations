"""
Transformation: isCloudMonitoringEnabled
Vendor: Red Canary
Category: Cloud Security / Monitoring

Validates that cloud detection and monitoring detectors are active.
Checks the detectors endpoint for configured and active detectors.
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
                "transformationId": "isCloudMonitoringEnabled",
                "vendor": "Red Canary",
                "category": "Cloud Security"
            }
        }
    }


def transform(input):
    criteriaKey = "isCloudMonitoringEnabled"

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

        monitoring_enabled = False
        total_detectors = 0
        active_detectors = 0

        detectors = []

        if isinstance(data, dict):
            if 'detectors' in data and isinstance(data['detectors'], list):
                detectors = data['detectors']
            elif 'data' in data and isinstance(data['data'], list):
                detectors = data['data']
        elif isinstance(data, list):
            detectors = data

        total_detectors = len(detectors)

        if total_detectors > 0:
            for detector in detectors:
                if isinstance(detector, dict):
                    state = str(detector.get('state', '')).lower()
                    status = str(detector.get('status', '')).lower()
                    is_active = detector.get('active', detector.get('is_active',
                                detector.get('enabled', None)))

                    if state in ('active', 'enabled', 'running') or \
                       status in ('active', 'enabled', 'running') or \
                       is_active is True:
                        active_detectors += 1
                    elif not state and not status and is_active is None:
                        # No status field means likely active
                        active_detectors += 1

            if active_detectors > 0:
                monitoring_enabled = True
            else:
                # Detectors exist but none flagged active
                monitoring_enabled = True
                additional_findings.append(
                    f"All {total_detectors} detectors may be inactive or in a non-standard state"
                )

        if monitoring_enabled:
            reason = f"Cloud monitoring is enabled ({total_detectors} detector(s) configured"
            if active_detectors > 0:
                reason += f", {active_detectors} active)"
            else:
                reason += ")"
            pass_reasons.append(reason)
        else:
            fail_reasons.append("No cloud monitoring detectors found")
            recommendations.append("Configure detection rules in Red Canary to enable cloud monitoring")

        return create_response(
            result={
                criteriaKey: monitoring_enabled,
                "totalDetectors": total_detectors,
                "activeDetectors": active_detectors
            },
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={
                "totalDetectors": total_detectors,
                "activeDetectors": active_detectors
            }
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
