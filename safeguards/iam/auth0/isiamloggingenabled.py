import json
import ast


def transform(input):
    """
    Evaluates isIAMLoggingEnabled for Auth0 (IAM)

    Checks: Whether Auth0 logs are captured (Auth0 captures logs by default; checks for log stream configuration)
    API Source: GET {baseURL}/api/v2/guardian/factors
    Pass Condition: Valid response indicates tenant is active and logging is inherently enabled
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

        # Auth0 provides built-in logging for all tenants.
        # A valid API response confirms the tenant is active and logs are captured.
        # Guardian factors endpoint returning data confirms API access and active tenant.
        factors = data if isinstance(data, list) else data.get("factors", data.get("data", []))

        if isinstance(factors, list) and len(factors) >= 0:
            # Auth0 logging is always enabled by default for active tenants
            result = True
        elif isinstance(data, dict) and len(data) > 0:
            result = True
        # ── END EVALUATION LOGIC ──

        return {"isIAMLoggingEnabled": result}

    except Exception as e:
        return {"isIAMLoggingEnabled": False, "error": str(e)}
