"""
Transformation: firewall_transform
Vendor: Firewall
Category: Network Security / Firewall

Evaluates if Firewalls are set up properly.
"""

import json
import ast
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
                "transformationId": "firewall_transform",
                "vendor": "Firewall",
                "category": "Network Security"
            }
        }
    }


def transform(input):
    is_firewall_enabled = False
    is_firewall_logging_enabled = False

    try:
        def _parse_input(input):
            if isinstance(input, str):
                try:
                    parsed = ast.literal_eval(input)
                    if isinstance(parsed, dict):
                        return parsed
                except:
                    pass
                try:
                    input = input.replace("'", '"')
                    return json.loads(input)
                except:
                    raise ValueError("Input string is neither valid Python literal nor JSON")
            if isinstance(input, bytes):
                return json.loads(input.decode("utf-8"))
            if isinstance(input, dict):
                return input
            raise ValueError("Input must be JSON string, bytes, or dict")

        input = _parse_input(input)
        data, validation = extract_input(input)

        if validation.get("status") == "failed":
            return create_response(
                result={"isFirewallEnabled": False, "isFirewallLoggingEnabled": False, "isFirewallConfigured": False},
                validation=validation,
                fail_reasons=["Input validation failed"]
            )

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        if isinstance(data, dict):
            if 'response' in data:
                data = _parse_input(data['response'])
            if 'result' in data:
                data = _parse_input(data['result'])

            is_firewall_enabled = True if data.get('isFirewallEnabled', False) else False
            is_firewall_logging_enabled = True if data.get('isFirewallLoggingEnabled', False) else False

        is_firewall_configured = is_firewall_enabled and is_firewall_logging_enabled

        additional_findings = []

        # Primary criteria: isFirewallEnabled
        if is_firewall_enabled:
            pass_reasons.append("Firewall is enabled")
        else:
            fail_reasons.append("Firewall not enabled or not reporting")
            recommendations.append("Enable firewall for network security")

        # Additional finding: isFirewallLoggingEnabled
        if is_firewall_logging_enabled:
            additional_findings.append({
                "metric": "isFirewallLoggingEnabled",
                "status": "pass",
                "reason": "Firewall logging is enabled"
            })
        else:
            additional_findings.append({
                "metric": "isFirewallLoggingEnabled",
                "status": "fail",
                "reason": "Firewall logging is not enabled",
                "recommendation": "Enable firewall logging for audit and compliance"
            })

        # Additional finding: isFirewallConfigured
        if is_firewall_configured:
            additional_findings.append({
                "metric": "isFirewallConfigured",
                "status": "pass",
                "reason": "Firewall is fully configured (enabled with logging)"
            })
        else:
            additional_findings.append({
                "metric": "isFirewallConfigured",
                "status": "fail",
                "reason": "Firewall configuration incomplete",
                "recommendation": "Ensure both firewall and logging are enabled"
            })

        return create_response(
            result={
                "isFirewallEnabled": is_firewall_enabled,
                "isFirewallLoggingEnabled": is_firewall_logging_enabled,
                "isFirewallConfigured": is_firewall_configured
            },
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={
                "firewallEnabled": is_firewall_enabled,
                "loggingEnabled": is_firewall_logging_enabled
            }
        )

    except Exception as e:
        return create_response(
            result={
                "isFirewallEnabled": False,
                "isFirewallLoggingEnabled": is_firewall_logging_enabled,
                "isFirewallConfigured": is_firewall_enabled and is_firewall_logging_enabled
            },
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
