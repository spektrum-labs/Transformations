"""
Transformation: isCloudPostureManagementEnabled
Vendor: Netskope
Category: Cloud Security / Posture Management

Evaluates whether the Netskope CSPM/SSPM module is licensed and active by
inspecting the alerts feed scoped to security assessment findings
(/api/v2/events/data/alert?type=securityassessment). The presence of
securityassessment-type alerts indicates that posture scanning policies are
running against connected IaaS or SaaS accounts and surfacing misconfigurations.
"""

import json
from datetime import datetime


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data.get("data"), input_data.get("validation")
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for attempt in range(3):
            unwrapped = False
            for key in wrapper_keys:
                if key in data and isinstance(data.get(key), dict):
                    data = data.get(key)
                    unwrapped = True
                    break
            if not unwrapped:
                break
    return data, {"status": "unknown", "errors": [], "warnings": ["Legacy input format"]}


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, transformation_errors=None,
                    api_errors=None, additional_findings=None):
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
                "transformationId": "isCloudPostureManagementEnabled",
                "vendor": "Netskope",
                "category": "Cloud Security"
            }
        }
    }


def transform(input):
    criteriaKey = "isCloudPostureManagementEnabled"

    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []

        alerts = []
        if isinstance(data, list):
            alerts = data
        elif isinstance(data, dict):
            for key in ("result", "data", "alerts", "items", "value"):
                value = data.get(key)
                if isinstance(value, list):
                    alerts = value
                    break

        alert_count = len(alerts) if isinstance(alerts, list) else 0

        severity_counts = {}
        service_breakdown = {}
        rule_counts = {}
        security_assessment_count = 0
        first_alert_timestamp = None
        last_alert_timestamp = None

        for alert in alerts:
            if not isinstance(alert, dict):
                continue

            alert_type = alert.get("alert_type") or alert.get("type") or ""
            if isinstance(alert_type, str) and alert_type.lower() == "securityassessment":
                security_assessment_count = security_assessment_count + 1

            severity = alert.get("severity") or alert.get("severity_level") or "unspecified"
            if isinstance(severity, str):
                severity_counts[severity] = severity_counts.get(severity, 0) + 1

            service = alert.get("service") or alert.get("cloud_provider") or alert.get("app")
            if isinstance(service, str) and service:
                service_breakdown[service] = service_breakdown.get(service, 0) + 1

            rule_name = alert.get("rule_name") or alert.get("policy") or alert.get("profile")
            if isinstance(rule_name, str) and rule_name:
                rule_counts[rule_name] = rule_counts.get(rule_name, 0) + 1

            timestamp = alert.get("timestamp") or alert.get("alert_timestamp")
            if isinstance(timestamp, (int, float)):
                if first_alert_timestamp is None or timestamp < first_alert_timestamp:
                    first_alert_timestamp = timestamp
                if last_alert_timestamp is None or timestamp > last_alert_timestamp:
                    last_alert_timestamp = timestamp

        posture_enabled = alert_count > 0

        if posture_enabled:
            pass_reasons.append(
                "Netskope CSPM/SSPM is generating findings: "
                + str(alert_count)
                + " security assessment alert(s) returned from /api/v2/events/data/alert"
            )
            additional_findings.append({"securityAssessmentAlertCount": security_assessment_count})
            if severity_counts:
                additional_findings.append({"severityBreakdown": severity_counts})
            if service_breakdown:
                additional_findings.append({"serviceBreakdown": service_breakdown})
            if rule_counts:
                additional_findings.append({"ruleBreakdown": rule_counts})
            if last_alert_timestamp is not None:
                additional_findings.append({"latestAlertTimestamp": last_alert_timestamp})
        else:
            fail_reasons.append(
                "No security assessment alerts were returned from /api/v2/events/data/alert?type=securityassessment - CSPM/SSPM module may not be licensed or enabled"
            )
            recommendations.append(
                "Confirm the CSPM/SSPM add-on is licensed, that posture profiles are assigned to connected IaaS/SaaS accounts, and that the REST API v2 token has access to /api/v2/events/data/alert"
            )

        return create_response(
            result={
                criteriaKey: posture_enabled,
                "alertCount": alert_count,
                "securityAssessmentCount": security_assessment_count
            },
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={
                "alertCount": alert_count,
                "securityAssessmentCount": security_assessment_count,
                "uniqueServices": len(service_breakdown),
                "uniqueRules": len(rule_counts)
            }
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
