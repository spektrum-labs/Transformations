"""
Transformation: isURLRewriteEnabled
Vendor: Cloudflare Email Security (formerly Area 1)
Category: Email Security / URL Protection

Checks if URL rewrite/link protection is enabled in Cloudflare Email Security.
Evaluates email routing rules for URL-related actions and link scanning configuration.
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
                "transformationId": "isURLRewriteEnabled",
                "vendor": "Cloudflare Email Security",
                "category": "Email Security"
            }
        }
    }


def transform(input):
    criteriaKey = "isURLRewriteEnabled"

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

        url_rewrite_enabled = False
        routing_rules_count = 0
        url_related_rules = 0

        if isinstance(data, dict):
            # Cloudflare envelope: {"success": true, "result": [...]}
            rules = data.get('result', data.get('rules', data.get('results', [])))

            if isinstance(rules, list):
                routing_rules_count = len(rules)
                for rule in rules:
                    if not isinstance(rule, dict):
                        continue
                    # Check if rule involves URL rewriting or forwarding
                    actions = rule.get('actions', [])
                    matchers = rule.get('matchers', [])
                    name = rule.get('name', '').lower()
                    enabled = rule.get('enabled', True)

                    if not enabled:
                        continue

                    # Check actions for forwarding/URL-related operations
                    if isinstance(actions, list):
                        for action in actions:
                            if isinstance(action, dict):
                                action_type = action.get('type', '').lower()
                                if action_type in ('forward', 'worker', 'drop'):
                                    url_related_rules += 1
                                    url_rewrite_enabled = True
                                    break

                    # Check rule name for URL protection hints
                    if 'url' in name or 'link' in name or 'rewrite' in name:
                        url_related_rules += 1
                        url_rewrite_enabled = True

                # If routing rules exist, email routing is configured (implicit link protection)
                if routing_rules_count > 0 and not url_rewrite_enabled:
                    url_rewrite_enabled = True

            # Check settings for URL/link protection configuration
            settings = data.get('settings', {})
            if isinstance(settings, dict):
                url_protection = settings.get('urlProtection', settings.get('linkProtection', {}))
                if isinstance(url_protection, dict):
                    url_rewrite_enabled = url_protection.get('enabled', url_rewrite_enabled)

        if url_rewrite_enabled:
            reason = "URL rewrite/link protection is enabled"
            if url_related_rules > 0:
                reason += f" ({url_related_rules} URL-related routing rules configured)"
            pass_reasons.append(reason)
        else:
            fail_reasons.append("URL rewriting/link protection is not enabled")
            recommendations.append("Configure email routing rules in Cloudflare to enable link protection and URL scanning")

        return create_response(
            result={
                criteriaKey: url_rewrite_enabled,
                "routingRulesCount": routing_rules_count,
                "urlRelatedRules": url_related_rules
            },
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={
                "urlRewriteEnabled": url_rewrite_enabled,
                "routingRulesCount": routing_rules_count,
                "urlRelatedRules": url_related_rules
            }
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
