import json
import ast


def transform(input):
    """Evaluates isStrongAuthRequired for Red Hat IDM (IAM)

    Checks: Whether OTP or multi-factor authentication is enforced in the
            IdM global configuration via the ipauserauthtype setting.
    API Source: POST {baseURL}/ipa/session/json (method: config_show)
    Pass Condition: ipauserauthtype includes 'otp', 'radius', or 'pkinit'.
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

        # config_show returns global IdM config with ipauserauthtype
        config = data.get("config", data)
        if isinstance(config, dict):
            config = config.get("result", config)

        auth_types = []
        if isinstance(config, dict):
            auth_types = config.get("ipauserauthtype", config.get("authTypes", []))

        if isinstance(auth_types, list):
            strong_types = ["otp", "radius", "pkinit", "idp"]
            for auth_type in auth_types:
                if isinstance(auth_type, str) and auth_type.lower() in strong_types:
                    result = True
                    break
        elif isinstance(auth_types, str) and auth_types.lower() in ["otp", "radius", "pkinit", "idp"]:
            result = True

        # Also check policies array if present
        policies = data.get("policies", [])
        if isinstance(policies, list) and not result:
            for policy in policies:
                if isinstance(policy, dict):
                    policy_type = policy.get("type", "").lower()
                    if "mfa" in policy_type or "otp" in policy_type:
                        result = True
                        break
        # ── END EVALUATION LOGIC ──

        return {"isStrongAuthRequired": result}

    except Exception as e:
        return {"isStrongAuthRequired": False, "error": str(e)}
