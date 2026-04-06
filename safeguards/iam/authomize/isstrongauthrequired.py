import json
import ast


def transform(input):
    """
    Evaluates isStrongAuthRequired for Authomize (IAM)

    Checks: Whether MFA policies are enforced across connected identity providers
    API Source: GET {baseURL}/v2/policies
    Pass Condition: At least one MFA or strong authentication policy is active
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

        policies = data.get("policies", data.get("data", data.get("items", [])))

        if isinstance(policies, list):
            mfa_policies = []
            for policy in policies:
                policy_type = str(policy.get("type", policy.get("category", ""))).lower()
                policy_name = str(policy.get("name", "")).lower()
                is_enabled = policy.get("enabled", policy.get("isEnabled", policy.get("active", False)))

                if is_enabled and ("mfa" in policy_type or "mfa" in policy_name or
                                   "authentication" in policy_type or "strong" in policy_name):
                    mfa_policies.append(policy)

            result = len(mfa_policies) > 0
        # ── END EVALUATION LOGIC ──

        return {"isStrongAuthRequired": result}

    except Exception as e:
        return {"isStrongAuthRequired": False, "error": str(e)}
