"""
Transformation: isMacroBlockingEnabled
Vendor: Microsoft Defender for Office 365  |  Category: Email Security
Evaluates: Whether malware filter policies block macro-enabled Office file types.

Data source: Get-MalwareFilterPolicy (Exchange Online PowerShell)
Key fields: EnableFileFilter (bool), FileTypes (list of extensions)

Macro-enabled file types: .docm, .xlsm, .pptm, .dotm, .xlam, .potm, .ppam, .ppsm
"""
import json
from datetime import datetime


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for attempt in range(3):
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isMacroBlockingEnabled", "vendor": "Microsoft Defender for Office 365", "category": "Email Security"}
        }
    }


def parse_api_error(raw_error, source=None):
    """Parse raw API error into clean message with recommendation."""
    raw_lower = raw_error.lower() if raw_error else ''
    src = source or "external service"
    if '401' in raw_error:
        return (f"Could not connect to {src}: Authentication failed (HTTP 401)",
                f"Verify {src} credentials and permissions are valid")
    elif '403' in raw_error:
        return (f"Could not connect to {src}: Access denied (HTTP 403)",
                f"Verify the integration has required {src} permissions")
    else:
        clean = (raw_error[0:80] + "...") if len(raw_error) > 80 else raw_error
        return (f"Could not connect to {src}: {clean}",
                f"Check {src} credentials and configuration")


def to_bool(val):
    """Convert various truthy representations to bool."""
    if isinstance(val, bool):
        return val
    if isinstance(val, str):
        return val.lower() in ("true", "1", "yes")
    return bool(val)


MACRO_EXTENSIONS = {".docm", ".xlsm", ".pptm", ".dotm", ".xlam", ".potm", ".ppam", ".ppsm"}


def check_policy_macro_blocking(policy):
    """Check if a malware filter policy blocks macro-enabled file types."""
    if not isinstance(policy, dict):
        return False, []

    # EnableFileFilter enables the common attachment types filter which includes macro types
    file_filter_enabled = to_bool(policy.get("EnableFileFilter", False))

    # FileTypes contains specific blocked extensions
    file_types = policy.get("FileTypes", [])
    if not isinstance(file_types, list):
        file_types = []

    # Normalize extensions to lowercase with dot prefix
    normalized = set()
    for ft in file_types:
        if isinstance(ft, str):
            ext = ft.lower().strip()
            if not ext.startswith("."):
                ext = "." + ext
            normalized.add(ext)

    blocked_macros = MACRO_EXTENSIONS.intersection(normalized)

    # Policy blocks macros if file filter is on OR specific macro extensions are blocked
    blocks_macros = file_filter_enabled or len(blocked_macros) > 0

    return blocks_macros, list(blocked_macros)


def extract_policies_and_rules(data):
    """Extract policy and rule lists from various input shapes."""
    policies = []
    rules = []

    if isinstance(data, list):
        return data, []

    if isinstance(data, dict):
        raw_policies = data.get("policies")
        if isinstance(raw_policies, list):
            policies = raw_policies
        elif isinstance(raw_policies, dict):
            policies = [raw_policies]

        raw_rules = data.get("rules")
        if isinstance(raw_rules, list):
            rules = raw_rules
        elif isinstance(raw_rules, dict):
            rules = [raw_rules]

    return policies, rules


def evaluate(data):
    """Evaluate malware filter policies for macro blocking.

    Default policy always applies. Non-default policies need an associated
    MalwareFilterRule with State = 'Enabled'.
    """
    try:
        policies, rules = extract_policies_and_rules(data)

        if not policies:
            return {"isMacroBlockingEnabled": False, "error": "No malware filter policies found"}

        # Build rule map: policy name -> rule state
        rule_map = {}
        for rule in rules:
            if not isinstance(rule, dict):
                continue
            policy_name = rule.get("MalwareFilterPolicy", "")
            state = rule.get("State", "")
            if policy_name:
                rule_map[policy_name] = state

        blocking_policies = []
        non_blocking_policies = []
        findings = []

        for policy in policies:
            if not isinstance(policy, dict):
                continue
            name = policy.get("Name", policy.get("name", "Unknown"))
            is_default = to_bool(policy.get("IsDefault", False))

            # Determine if policy is active
            if is_default:
                is_active = True
            else:
                rule_state = rule_map.get(name, "")
                is_active = rule_state == "Enabled"

            if not is_active:
                findings.append(f"{name}: no active rule (not applied)")
                continue

            blocks_macros, blocked_exts = check_policy_macro_blocking(policy)
            file_filter = to_bool(policy.get("EnableFileFilter", False))

            if blocks_macros:
                blocking_policies.append(name)
                if file_filter:
                    findings.append(f"{name}: common attachment types filter enabled")
                else:
                    findings.append(f"{name}: blocking macro types: {', '.join(sorted(blocked_exts))}")
            else:
                non_blocking_policies.append(name)
                findings.append(f"{name}: active but no macro blocking configured")

        has_blocking = len(blocking_policies) > 0

        return {
            "isMacroBlockingEnabled": has_blocking,
            "totalPolicies": len(policies),
            "blockingPolicies": len(blocking_policies),
            "blockingPolicyNames": blocking_policies,
            "findings": list(findings[i] for i in range(min(10, len(findings))))
        }
    except Exception as e:
        return {"isMacroBlockingEnabled": False, "error": str(e)}


def transform(input):
    criteriaKey = "isMacroBlockingEnabled"
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        # Check for PowerShell/API error
        if isinstance(data, dict) and "PSError" in data:
            raw_error = data.get("PSError", "")
            api_error, recommendation = parse_api_error(raw_error, source="Microsoft 365")
            return create_response(
                result={criteriaKey: False},
                validation={"status": "skipped", "errors": [], "warnings": ["API returned error"]},
                api_errors=[api_error],
                fail_reasons=["Could not retrieve malware filter policies from Microsoft 365"],
                recommendations=[recommendation]
            )

        eval_result = evaluate(data)
        result_value = eval_result.get(criteriaKey, False)
        extra_fields = {k: v for k, v in eval_result.items() if k != criteriaKey and k != "error"}

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        if result_value:
            pass_reasons.append(f"{criteriaKey} check passed")
            names = eval_result.get("blockingPolicyNames", [])
            if names:
                pass_reasons.append(f"Policies blocking macros: {', '.join(list(names[i] for i in range(min(5, len(names)))))}")
        else:
            fail_reasons.append(f"{criteriaKey} check failed")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Enable the common attachment types filter (EnableFileFilter) or block macro file types (.docm, .xlsm, .pptm, .dotm) in malware filter policies")

        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={criteriaKey: result_value, "totalPolicies": extra_fields.get("totalPolicies", 0), "blockingPolicies": extra_fields.get("blockingPolicies", 0)},
            additional_findings=eval_result.get("findings", [])
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
