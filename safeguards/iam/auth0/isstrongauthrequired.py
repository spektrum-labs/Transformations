import json
import ast


def transform(input):
    """
    Evaluates isStrongAuthRequired for Auth0 (IAM)

    Checks: Whether MFA is enforced via Guardian factors
    API Source: GET {baseURL}/api/v2/guardian/factors
    Pass Condition: At least one Guardian MFA factor (sms, push, otp, email, webauthn) is enabled
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

        # Auth0 Guardian factors returns a list of factor objects with name and enabled fields
        factors = data if isinstance(data, list) else data.get("factors", data.get("data", []))

        if isinstance(factors, list):
            enabled_factors = [f for f in factors if f.get("enabled", False) is True]
            # Strong auth requires at least one MFA factor enabled
            result = len(enabled_factors) > 0
        # ── END EVALUATION LOGIC ──

        return {"isStrongAuthRequired": result}

    except Exception as e:
        return {"isStrongAuthRequired": False, "error": str(e)}
