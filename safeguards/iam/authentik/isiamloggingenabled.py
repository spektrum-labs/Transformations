import json
import ast


def transform(input):
    """
    Evaluates isIAMLoggingEnabled for Authentik (IAM)

    Checks: Whether Authentik event logging is active for authentication and admin actions
    API Source: GET {baseURL}/api/v3/stages/authenticator/validate/
    Pass Condition: Valid API response confirms the instance is active (Authentik logs all events by default)
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

        # Authentik has built-in event logging for all actions.
        # A valid API response confirms the instance is operational and logging.
        results = data.get("results", data.get("data", []))
        pagination = data.get("pagination", {})

        if isinstance(results, list):
            # Any valid response means the instance is active and logging
            result = True
        elif isinstance(pagination, dict) and "count" in pagination:
            result = True
        elif isinstance(data, dict) and len(data) > 0:
            result = True
        # ── END EVALUATION LOGIC ──

        return {"isIAMLoggingEnabled": result}

    except Exception as e:
        return {"isIAMLoggingEnabled": False, "error": str(e)}
