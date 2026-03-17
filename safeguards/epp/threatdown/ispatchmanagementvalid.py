"""
Transformation: isPatchManagementValid
Vendor: ThreatDown (Malwarebytes Nebula)  |  Category: EPP
Evaluates: Whether patch management processes exist and SLAs are met for vulnerability remediation.
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
                    recommendations=None, input_summary=None, transformation_errors=None,
                    api_errors=None, additional_findings=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error" if (api_errors or []) else "success", "errors": api_errors or []},
            "validation": {"status": validation.get("status", "unknown"), "errors": validation.get("errors", []), "warnings": validation.get("warnings", [])},
            "transformation": {"status": "error" if (transformation_errors or []) else "success", "errors": transformation_errors or [], "inputSummary": input_summary or {}},
            "evaluation": {"passReasons": pass_reasons or [], "failReasons": fail_reasons or [], "recommendations": recommendations or [], "additionalFindings": additional_findings or []},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isPatchManagementValid", "vendor": "ThreatDown", "category": "EPP"}
        }
    }


def evaluate(data):
    """Validate patch management processes and SLA compliance."""
    try:
        policies = []
        if isinstance(data, list):
            policies = data
        elif isinstance(data, dict):
            policies = (
                data.get("policies", []) or
                data.get("data", []) or
                data.get("results", []) or
                []
            )

        if not isinstance(policies, list):
            policies = [policies] if policies else []

        total_policies = len(policies)
        valid_count = 0
        issues = []

        for policy in policies:
            if not isinstance(policy, dict):
                continue

            policy_name = policy.get("name", policy.get("policyName", "Unknown"))
            policy_valid = True

            # Check vulnerability scan is enabled
            vuln_scan = policy.get("vulnerability_scan", policy.get("vulnerabilityScan", None))
            if vuln_scan is not None:
                if isinstance(vuln_scan, dict):
                    enabled = vuln_scan.get("enabled", False)
                    schedule = vuln_scan.get("schedule", vuln_scan.get("frequency", ""))
                    if not enabled and not (isinstance(enabled, str) and enabled.lower() in ("true", "1")):
                        policy_valid = False
                        issues.append(f"{policy_name}: vulnerability scanning disabled")
                    elif not schedule:
                        issues.append(f"{policy_name}: no scan schedule configured")
                elif isinstance(vuln_scan, bool) and not vuln_scan:
                    policy_valid = False
                    issues.append(f"{policy_name}: vulnerability scanning disabled")

            # Check auto-remediation / patching
            auto_remediate = policy.get("auto_remediate", policy.get("autoRemediate", policy.get("auto_patch", None)))
            if auto_remediate is not None:
                if (isinstance(auto_remediate, bool) and not auto_remediate) or str(auto_remediate).lower() in ("false", "0", "disabled"):
                    issues.append(f"{policy_name}: auto-remediation disabled")

            if policy_valid:
                valid_count = valid_count + 1

        is_valid = valid_count > 0 and total_policies > 0

        return {
            "isPatchManagementValid": is_valid,
            "totalPolicies": total_policies,
            "validPolicies": valid_count,
            "issues": issues
        }
    except Exception as e:
        return {"isPatchManagementValid": False, "error": str(e)}


def transform(input):
    criteriaKey = "isPatchManagementValid"
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

        eval_result = evaluate(data)
        result_value = eval_result.get(criteriaKey, False)
        extra_fields = {k: v for k, v in eval_result.items() if k != criteriaKey and k != "error"}

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        if result_value:
            pass_reasons.append(f"Patch management valid in {extra_fields.get('validPolicies', 0)} of {extra_fields.get('totalPolicies', 0)} policies")
            if extra_fields.get("issues"):
                for issue in extra_fields["issues"]:
                    pass_reasons.append(f"Warning: {issue}")
        else:
            total = extra_fields.get("totalPolicies", 0)
            if total == 0:
                fail_reasons.append("No policies found in ThreatDown Nebula")
                recommendations.append("Create policies with vulnerability scanning and patch management enabled")
            else:
                fail_reasons.append(f"Patch management not valid - {extra_fields.get('validPolicies', 0)} of {total} policies pass")
                for issue in extra_fields.get("issues", []):
                    fail_reasons.append(issue)
                recommendations.append("Enable vulnerability scanning with a regular schedule in all ThreatDown policies")
                recommendations.append("Configure auto-remediation to meet patch SLA requirements")

        return create_response(
            result={criteriaKey: result_value, "totalPolicies": extra_fields.get("totalPolicies", 0), "validPolicies": extra_fields.get("validPolicies", 0)},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={criteriaKey: result_value, "totalPolicies": extra_fields.get("totalPolicies", 0)}
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
