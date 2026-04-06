import json
import ast


def transform(input):
    """Evaluates isStrongAuthRequired for Silverfort (IAM)

    Checks: Whether MFA policies are enforced by checking Silverfort
            policies for active MFA-required authentication rules.
    API Source: GET {baseURL}/api/v2/policies
    Pass Condition: At least one active policy requires MFA or step-up auth.
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

        policies = data.get("policies", data)
        if isinstance(policies, dict):
            policies = policies.get("items", policies.get("data", []))

        if isinstance(policies, list) and len(policies) > 0:
            for policy in policies:
                if isinstance(policy, dict):
                    action = str(policy.get("action", policy.get("authAction", ""))).lower()
                    enabled = policy.get("enabled", policy.get("active", True))
                    policy_type = str(policy.get("type", policy.get("authType", ""))).lower()

                    if not enabled:
                        continue

                    # Check for MFA enforcement actions
                    if "mfa" in action or "block" in action or "step_up" in action:
                        result = True
                        break
                    if "mfa" in policy_type or "multi" in policy_type:
                        result = True
                        break
                    # Silverfort policies that require additional verification
                    if action in ["require_mfa", "challenge", "deny", "alert_and_mfa"]:
                        result = True
                        break
        # ── END EVALUATION LOGIC ──

        return {"isStrongAuthRequired": result}

    except Exception as e:
        return {"isStrongAuthRequired": False, "error": str(e)}
