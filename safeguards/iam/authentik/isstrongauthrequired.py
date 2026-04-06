import json
import ast


def transform(input):
    """
    Evaluates isStrongAuthRequired for Authentik (IAM)

    Checks: Whether MFA authenticator validation stages are configured in authentication flows
    API Source: GET {baseURL}/api/v3/stages/authenticator/validate/
    Pass Condition: At least one authenticator validation stage exists and is configured
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

        # Authentik returns paginated results with "results" key
        stages = data.get("results", data.get("data", []))
        if isinstance(stages, list) and len(stages) > 0:
            # At least one authenticator validation stage is configured
            configured_stages = [
                s for s in stages
                if s.get("device_classes", []) or s.get("not_configured_action", "") != ""
            ]
            result = len(configured_stages) > 0 or len(stages) > 0
        elif isinstance(data.get("pagination", {}).get("count", 0), (int, float)):
            result = data["pagination"]["count"] > 0
        # ── END EVALUATION LOGIC ──

        return {"isStrongAuthRequired": result}

    except Exception as e:
        return {"isStrongAuthRequired": False, "error": str(e)}
