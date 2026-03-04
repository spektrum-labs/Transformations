"""
Transformation: isSSLInspectionEnabled
Vendor: Zscaler ZIA
Category: SASE / SSL Inspection

Evaluates if SSL/TLS inspection is enabled in Zscaler ZIA.
Checks for SSL inspection settings and rules that indicate encrypted
traffic analysis is active.
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
                "transformationId": "isSSLInspectionEnabled",
                "vendor": "Zscaler ZIA",
                "category": "SASE"
            }
        }
    }


def transform(input):
    criteriaKey = "isSSLInspectionEnabled"

    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        if validation.get("status") == "failed":
            return create_response(
                result={criteriaKey: False, "sslRulesCount": 0},
                validation=validation,
                fail_reasons=["Input validation failed"]
            )

        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []

        isSSLInspectionEnabled = False
        ssl_rules_count = 0
        decrypt_rules_count = 0

        # Handle raw list input (API returns array of rules directly)
        ssl_rules = None
        if isinstance(data, list):
            ssl_rules = data
        elif isinstance(data, dict):
            ssl_settings = data.get('sslInspectionRules', data.get('responseData', {}))

            # Handle if settings is a dict (single config)
            if isinstance(ssl_settings, dict):
                if ssl_settings.get('sslInterceptionEnabled', False):
                    isSSLInspectionEnabled = True
                if ssl_settings.get('enabled', False):
                    isSSLInspectionEnabled = True
                if ssl_settings.get('sslDecryptionEnabled', False):
                    isSSLInspectionEnabled = True

                # Check for inspection certificates
                if ssl_settings.get('certificates') or ssl_settings.get('rootCertificate'):
                    isSSLInspectionEnabled = True

            elif isinstance(ssl_settings, list):
                ssl_rules = ssl_settings

            # Check for any SSL-related configuration indicators
            if data.get('sslScanEnabled') or data.get('sslInterception'):
                isSSLInspectionEnabled = True

        # Process rules list (from raw input or dict key)
        if isinstance(ssl_rules, list):
            ssl_rules_count = len(ssl_rules)
            if ssl_rules_count > 0:
                isSSLInspectionEnabled = True

                for rule in ssl_rules:
                    if not isinstance(rule, dict):
                        continue
                    state = rule.get('state', rule.get('status', '')).upper()
                    if state == 'ENABLED' or rule.get('enabled', False):
                        # Check if this is a DECRYPT rule
                        action = rule.get('action', {})
                        if isinstance(action, dict) and action.get('type') == 'DECRYPT':
                            decrypt_rules_count += 1

        if decrypt_rules_count > 0:
            additional_findings.append({
                "metric": "decryptRulesCount",
                "status": "pass",
                "reason": f"{decrypt_rules_count} active DECRYPT rules configured"
            })

        if isSSLInspectionEnabled:
            pass_reasons.append(f"SSL/TLS inspection is enabled ({ssl_rules_count} rules, {decrypt_rules_count} decrypt)")
        else:
            fail_reasons.append("SSL/TLS inspection is not configured")
            recommendations.append("Enable SSL inspection in Zscaler ZIA for encrypted traffic analysis")

        return create_response(
            result={criteriaKey: isSSLInspectionEnabled, "sslRulesCount": ssl_rules_count},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={
                "totalRules": ssl_rules_count,
                "decryptRules": decrypt_rules_count
            }
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False, "sslRulesCount": 0},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
