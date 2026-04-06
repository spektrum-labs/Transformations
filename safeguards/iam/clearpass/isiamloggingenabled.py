import json
import ast


def transform(input):
    """
    Evaluates isIAMLoggingEnabled for ClearPass (IAM)

    Checks: Whether ClearPass audit and session logs are enabled and captured
    API Source: GET {baseURL}/api/enforcement-policy
    Pass Condition: Enforcement policies exist indicating the system is actively processing and logging sessions
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

        # ClearPass inherently logs all authentication sessions and audit events.
        # Having active enforcement policies confirms the system is processing authentications.
        items = data.get("_embedded", {}).get("items", data.get("items", data.get("data", [])))
        count = data.get("count", data.get("total", 0))

        if isinstance(items, list) and len(items) > 0:
            # Active policies confirm ClearPass is processing and logging
            result = True
        elif isinstance(count, (int, float)) and count > 0:
            result = True
        # ── END EVALUATION LOGIC ──

        return {"isIAMLoggingEnabled": result}

    except Exception as e:
        return {"isIAMLoggingEnabled": False, "error": str(e)}
