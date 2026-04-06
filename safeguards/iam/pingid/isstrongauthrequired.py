import json
import ast


def transform(input):
    """Evaluates isStrongAuthRequired for PingID / PingOne (IAM)

    Checks that MFA policies are configured and enabled in the PingOne
    environment by inspecting MFA policy status.

    Parameters:
        input (dict): JSON data containing API response from getEstateMFAStatus

    Returns:
        dict: {"isStrongAuthRequired": boolean}
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

        # PingOne /mfaPolicies returns embedded policies
        embedded = data.get("_embedded", data)
        policies = embedded.get("mfaPolicies", data.get("policies", []))

        if isinstance(policies, list) and len(policies) > 0:
            enabled_count = 0
            for policy in policies:
                enabled = policy.get("enabled", policy.get("status", ""))
                if enabled is True or str(enabled).upper() == "ENABLED":
                    enabled_count += 1
            result = enabled_count > 0
        # ── END EVALUATION LOGIC ──

        return {"isStrongAuthRequired": result}

    except Exception as e:
        return {"isStrongAuthRequired": False, "error": str(e)}
