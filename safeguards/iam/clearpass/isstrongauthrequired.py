import json
import ast


def transform(input):
    """
    Evaluates isStrongAuthRequired for ClearPass (IAM)

    Checks: Whether strong authentication methods (802.1X, certificates) are enforced in enforcement policies
    API Source: GET {baseURL}/api/enforcement-policy
    Pass Condition: At least one enforcement policy uses 802.1X or certificate-based authentication
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

        # ClearPass enforcement policies contain enforcement_type and rules
        items = data.get("_embedded", {}).get("items", data.get("items", data.get("data", [])))

        if isinstance(items, list) and len(items) > 0:
            strong_auth_policies = []
            for policy in items:
                enforcement_type = str(policy.get("enforcement_type", "")).lower()
                policy_name = str(policy.get("name", "")).lower()
                default_action = str(policy.get("default_enforcement_profile", "")).lower()

                # 802.1X, RADIUS, or certificate-based enforcement indicates strong auth
                if any(keyword in enforcement_type or keyword in policy_name
                       for keyword in ["802.1x", "radius", "certificate", "eap", "tls"]):
                    strong_auth_policies.append(policy)

            result = len(strong_auth_policies) > 0
        # ── END EVALUATION LOGIC ──

        return {"isStrongAuthRequired": result}

    except Exception as e:
        return {"isStrongAuthRequired": False, "error": str(e)}
