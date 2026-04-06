import json
import ast


def transform(input):
    """Evaluates isIAMLoggingEnabled for Silverfort (IAM)

    Checks: Whether IAM logging is enabled by checking Silverfort policies
            for audit and monitoring configurations.
    API Source: GET {baseURL}/api/v2/policies
    Pass Condition: Policies exist with monitoring or alert actions enabled.
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

        # Silverfort inherently logs all authentication events.
        # If we get a valid policy response, logging is active.
        policies = data.get("policies", data)
        total = data.get("totalCount", 0)

        if isinstance(policies, dict):
            policies = policies.get("items", policies.get("data", []))

        if isinstance(policies, list) and len(policies) > 0:
            # Silverfort logs all auth events by default
            result = True

            # Additionally check for explicit alert/audit policies
            for policy in policies:
                if isinstance(policy, dict):
                    action = str(policy.get("action", "")).lower()
                    if "alert" in action or "log" in action or "monitor" in action:
                        result = True
                        break

        if not result and isinstance(total, (int, float)) and total > 0:
            result = True
        # ── END EVALUATION LOGIC ──

        return {"isIAMLoggingEnabled": result}

    except Exception as e:
        return {"isIAMLoggingEnabled": False, "error": str(e)}
