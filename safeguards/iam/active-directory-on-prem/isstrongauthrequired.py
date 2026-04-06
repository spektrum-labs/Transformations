import json
import ast


def transform(input):
    """
    Evaluates isStrongAuthRequired for Active Directory On-Prem (IAM)

    Checks: Whether smart card or MFA is enforced for interactive logon via AD policies
    API Source: GET {baseURL}/api/policies/authentication
    Pass Condition: Authentication policies indicate smart card or MFA requirement is enabled
    """
    try:
        def _parse_input(raw):
            if isinstance(raw, str):
                try:
                    parsed = ast.literal_eval(raw)
                    if isinstance(parsed, dict):
                        return parsed
                except:
                    pass
                try:
                    raw = raw.replace("'", '"')
                    return json.loads(raw)
                except:
                    raise ValueError("Input string is neither valid Python literal nor JSON")
            if isinstance(raw, bytes):
                return json.loads(raw.decode("utf-8"))
            if isinstance(raw, dict):
                return raw
            raise ValueError("Input must be JSON string, bytes, or dict")

        data = _parse_input(input)
        data = data.get("response", data)
        data = data.get("result", data)
        data = data.get("apiResponse", data)

        # ── EVALUATION LOGIC ──
        result = False

        # Check for smart card requirement or MFA enforcement
        smart_card_required = data.get("smartCardRequired", data.get("smartcardRequired", False))
        mfa_enabled = data.get("mfaEnabled", data.get("mfaEnforced", False))
        policies = data.get("policies", data.get("authenticationPolicies", []))

        if smart_card_required or mfa_enabled:
            result = True
        elif isinstance(policies, list):
            for policy in policies:
                policy_type = str(policy.get("type", "")).lower()
                enabled = policy.get("enabled", policy.get("isEnabled", False))
                if policy_type in ("smartcard", "mfa", "certificate", "multifactor") and enabled:
                    result = True
                    break
        # ── END EVALUATION LOGIC ──

        return {"isStrongAuthRequired": result}

    except Exception as e:
        return {"isStrongAuthRequired": False, "error": str(e)}
