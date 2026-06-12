"""
Transformation: isMisconfigurationDetectionEnabled
Vendor: Netskope
Category: Cloud Security / Misconfiguration Detection

Validates that policy enforcement and misconfiguration detection (DLP,
real-time protection, threat protection) is active by inspecting recent policy
alerts (/api/v2/events/data/alert?type=policy). The presence of policy-type
alerts confirms Netskope is matching traffic against active inline and SaaS
API policies and flagging policy violations or risky behavior.
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
                "transformationId": "isMisconfigurationDetectionEnabled",
                "vendor": "Netskope",
                "category": "Cloud Security"
            }
        }
    }


def transform(input):
    criteriaKey = "isMisconfigurationDetectionEnabled"

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

        policy_alert_count = 0
        policy_breakdown = {}
        action_breakdown = {}
        app_breakdown = {}
        severity_counts = {}
        block_action_count = 0

        block_actions = ("block", "deny", "quarantine", "tombstone")

        for alert in alerts:
            if not isinstance(alert, dict):
                continue

            alert_type = alert.get("alert_type") or alert.get("type") or ""
            if isinstance(alert_type, str) and alert_type.lower() == "policy":
                policy_alert_count = policy_alert_count + 1

            policy_name = alert.get("policy") or alert.get("policy_name") or alert.get("profile")
            if isinstance(policy_name, str) and policy_name:
                policy_breakdown[policy_name] = policy_breakdown.get(policy_name, 0) + 1

            action = alert.get("action") or alert.get("policy_action")
            if isinstance(action, str) and action:
                action_lower = action.lower()
                action_breakdown[action] = action_breakdown.get(action, 0) + 1
                if action_lower in block_actions:
                    block_action_count = block_action_count + 1

            app_name = alert.get("app") or alert.get("application") or alert.get("appname")
            if isinstance(app_name, str) and app_name:
                app_breakdown[app_name] = app_breakdown.get(app_name, 0) + 1

            severity = alert.get("severity") or alert.get("severity_level")
            if isinstance(severity, str) and severity:
                severity_counts[severity] = severity_counts.get(severity, 0) + 1

        detection_active = alert_count > 0

        if detection_active:
            pass_reasons.append(
                "Netskope policy enforcement is active: "
                + str(alert_count)
                + " policy alert(s) returned across "
                + str(len(policy_breakdown))
                + " unique policy(ies)"
            )
            additional_findings.append({"policyAlertCount": policy_alert_count})
            if block_action_count > 0:
                additional_findings.append({"blockOrQuarantineActionCount": block_action_count})
            if policy_breakdown:
                additional_findings.append({"policyBreakdown": policy_breakdown})
            if action_breakdown:
                additional_findings.append({"actionBreakdown": action_breakdown})
            if app_breakdown:
                additional_findings.append({"appBreakdown": app_breakdown})
            if severity_counts:
                additional_findings.append({"severityBreakdown": severity_counts})
        else:
            fail_reasons.append(
                "No policy alerts were returned from /api/v2/events/data/alert?type=policy - misconfiguration / policy enforcement cannot be confirmed"
            )
            recommendations.append(
                "Verify that real-time protection or API-driven SaaS policies are configured and that the REST API v2 token has access to /api/v2/events/data/alert"
            )

        return create_response(
            result={
                criteriaKey: detection_active,
                "policyAlertCount": policy_alert_count,
                "totalAlerts": alert_count,
                "uniquePolicies": len(policy_breakdown),
                "blockActionCount": block_action_count
            },
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={
                "totalAlerts": alert_count,
                "policyAlertCount": policy_alert_count,
                "uniquePolicies": len(policy_breakdown),
                "uniqueApps": len(app_breakdown)
            }
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
