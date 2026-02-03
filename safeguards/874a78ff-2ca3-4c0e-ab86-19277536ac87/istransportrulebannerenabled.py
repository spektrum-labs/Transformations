"""
Transformation: isTransportRuleBannerEnabled
Vendor: Microsoft
Category: Email Security / Transport Rules

Evaluates if transport rule banner is enabled by checking for rules with Disclaimer or SubjectPrefix actions.
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
                "transformationId": "isTransportRuleBannerEnabled",
                "vendor": "Microsoft",
                "category": "Email Security"
            }
        }
    }



def parse_api_error(raw_error: str, source: str = None) -> tuple:
    """Parse raw API error into clean message with source."""
    raw_lower = raw_error.lower() if raw_error else ''
    src = source or "external service"

    if '401' in raw_error:
        return (f"Could not connect to {src}: Authentication failed (HTTP 401)",
                f"Verify {src} credentials and permissions are valid")
    elif '403' in raw_error:
        return (f"Could not connect to {src}: Access denied (HTTP 403)",
                f"Verify the integration has required {src} permissions")
    elif '404' in raw_error:
        return (f"Could not connect to {src}: Resource not found (HTTP 404)",
                f"Verify the {src} resource and configuration exist")
    elif '429' in raw_error:
        return (f"Could not connect to {src}: Rate limited (HTTP 429)",
                "Retry the request after waiting")
    elif '500' in raw_error or '502' in raw_error or '503' in raw_error:
        return (f"Could not connect to {src}: Service unavailable (HTTP 5xx)",
                f"{src} may be temporarily unavailable, retry later")
    elif 'timeout' in raw_lower:
        return (f"Could not connect to {src}: Request timed out",
                "Check network connectivity and retry")
    elif 'connection' in raw_lower:
        return (f"Could not connect to {src}: Connection failed",
                "Check network connectivity and firewall settings")
    else:
        clean = raw_error[:80] + "..." if len(raw_error) > 80 else raw_error
        return (f"Could not connect to {src}: {clean}",
                f"Check {src} credentials and configuration")

def transform(input):
    criteriaKey = "isTransportRuleBannerEnabled"

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


        # Check for API error (e.g., OAuth failure)
        if isinstance(data, dict) and 'PSError' in data:
            api_error, recommendation = parse_api_error(data.get('PSError', ''), source="Microsoft 365")
            return create_response(
                result={criteriaKey: False},
                validation={"status": "skipped", "errors": [], "warnings": ["API returned error"]},
                api_errors=[api_error],
                fail_reasons=["Could not retrieve data from Microsoft 365"],
                recommendations=[recommendation]
            )

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        transport_rules = data.get("transportRules", [])
        banner_rules = []

        for rule in transport_rules:
            actions = rule.get('Actions', [])
            if actions:
                matching_actions = [action for action in actions if ('Disclaimer' in action or 'SubjectPrefix' in action)]
                if matching_actions:
                    banner_rules.append({
                        'Name': rule.get('Name', 'Unknown'),
                        'State': rule.get('State', 'Unknown'),
                        'Mode': rule.get('Mode', 'Unknown')
                    })

        # Check if any banner rule is enabled
        enabled_rules = [rule for rule in banner_rules if rule['State'] == 'Enabled']
        is_enabled = len(enabled_rules) > 0

        if is_enabled:
            rule_names = [r['Name'] for r in enabled_rules[:3]]
            pass_reasons.append(f"Transport rule banner enabled via {len(enabled_rules)} rules: {', '.join(rule_names)}")
        else:
            if len(banner_rules) > 0:
                fail_reasons.append(f"Found {len(banner_rules)} banner rules but none are enabled")
            else:
                fail_reasons.append("No transport rules with Disclaimer or SubjectPrefix actions found")
            recommendations.append("Enable transport rules with banner/disclaimer actions for external email warnings")

        return create_response(
            result={criteriaKey: is_enabled, "totalRules": len(transport_rules), "bannerRulesCount": len(banner_rules)},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={"totalRules": len(transport_rules), "bannerRules": len(banner_rules), "enabledBannerRules": len(enabled_rules)}
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
