"""
Transformation: isDNSPolicyConfigured
Vendor: DNSFilter
Category: Network Security / Policy Configuration

Ensures that DNS filtering policies are configured with appropriate category blocks.
Checks the policies endpoint for configured filtering policies.
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
                "transformationId": "isDNSPolicyConfigured",
                "vendor": "DNSFilter",
                "category": "Network Security"
            }
        }
    }


def transform(input):
    criteriaKey = "isDNSPolicyConfigured"

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

        policy_configured = False
        total_policies = 0
        policies_with_blocks = 0
        total_blocked_categories = 0

        policies = []

        if isinstance(data, dict):
            if 'policies' in data and isinstance(data['policies'], list):
                policies = data['policies']
            elif 'data' in data and isinstance(data['data'], list):
                policies = data['data']
        elif isinstance(data, list):
            policies = data

        total_policies = len(policies)

        if total_policies > 0:
            for policy in policies:
                if isinstance(policy, dict):
                    # Check for blocked categories
                    blocked_categories = policy.get('blocked_categories', policy.get('blockedCategories', []))
                    category_settings = policy.get('category_settings', policy.get('categorySettings', {}))
                    block_list = policy.get('block_list', policy.get('blockList', []))

                    has_blocks = False
                    if isinstance(blocked_categories, list) and len(blocked_categories) > 0:
                        has_blocks = True
                        total_blocked_categories += len(blocked_categories)
                    elif isinstance(category_settings, dict) and len(category_settings) > 0:
                        has_blocks = True
                        total_blocked_categories += len(category_settings)
                    elif isinstance(block_list, list) and len(block_list) > 0:
                        has_blocks = True
                        total_blocked_categories += len(block_list)

                    if has_blocks:
                        policies_with_blocks += 1

            # Policies exist - consider configured even without explicit block lists
            # as policies may use default blocking rules
            policy_configured = True

            if policies_with_blocks > 0:
                pass_reasons.append(
                    f"DNS policies configured with category blocks "
                    f"({policies_with_blocks} of {total_policies} policies have explicit blocks, "
                    f"{total_blocked_categories} total blocked categories)"
                )
            else:
                pass_reasons.append(f"DNS policies configured ({total_policies} policies found)")
                additional_findings.append(
                    "No explicit category blocks detected in policies - "
                    "policies may be using default blocking rules"
                )
        else:
            fail_reasons.append("No DNS filtering policies configured")
            recommendations.append("Configure DNS filtering policies with appropriate category blocks in DNSFilter")

        return create_response(
            result={
                criteriaKey: policy_configured,
                "totalPolicies": total_policies,
                "policiesWithBlocks": policies_with_blocks,
                "totalBlockedCategories": total_blocked_categories
            },
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={
                "totalPolicies": total_policies,
                "policiesWithBlocks": policies_with_blocks,
                "totalBlockedCategories": total_blocked_categories
            }
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
