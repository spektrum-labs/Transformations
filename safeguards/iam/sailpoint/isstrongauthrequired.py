import json
import ast


def transform(input):
    """Evaluates isStrongAuthRequired for SailPoint IdentityNow (IAM)

    Checks: Whether MFA is enforced by checking the MFA configuration
            for enabled authentication factors.
    API Source: GET {baseURL}/v3/mfa-configuration
    Pass Condition: At least one MFA method is enabled in the tenant config.
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

        mfa_config = data.get("mfaConfig", data)
        if isinstance(mfa_config, dict):
            # Check for any enabled MFA method
            enabled = mfa_config.get("enabled", mfa_config.get("mfaEnabled", None))
            if isinstance(enabled, bool) and enabled:
                result = True

            # Check individual MFA methods
            methods = mfa_config.get("methods", mfa_config.get("factors", []))
            if isinstance(methods, list):
                for method in methods:
                    if isinstance(method, dict) and method.get("enabled", False):
                        result = True
                        break

            # Check duo, okta-verify, etc.
            for key in ["duo", "okta", "google", "sms", "email", "totp"]:
                method_cfg = mfa_config.get(key, {})
                if isinstance(method_cfg, dict) and method_cfg.get("enabled", False):
                    result = True
                    break

        # Check if response is a list of MFA configs
        if isinstance(mfa_config, list):
            for cfg in mfa_config:
                if isinstance(cfg, dict) and cfg.get("enabled", False):
                    result = True
                    break

        # Check policies array
        policies = data.get("policies", [])
        if isinstance(policies, list) and not result:
            for policy in policies:
                if isinstance(policy, dict):
                    action = policy.get("action", "").lower()
                    if "mfa" in action or "step_up" in action:
                        result = True
                        break
        # ── END EVALUATION LOGIC ──

        return {"isStrongAuthRequired": result}

    except Exception as e:
        return {"isStrongAuthRequired": False, "error": str(e)}
