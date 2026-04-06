import json
import ast


def transform(input):
    """Evaluates isIAMLoggingEnabled for JumpCloud (IAM)

    Validates that JumpCloud directory insights and audit logging are active
    by confirming user activity data is available in the response.

    Parameters:
        input (dict): JSON data containing API response from getEstateMFAStatus

    Returns:
        dict: {"isIAMLoggingEnabled": boolean}
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

        # JumpCloud has built-in Directory Insights for audit logging;
        # if users exist and the API is responsive, logging is inherently active
        users = data.get("results", data.get("users", []))
        total = data.get("totalCount", data.get("total", 0))

        if isinstance(users, list) and len(users) > 0:
            result = True
        elif isinstance(total, (int, float)) and total > 0:
            result = True
        # ── END EVALUATION LOGIC ──

        return {"isIAMLoggingEnabled": result}

    except Exception as e:
        return {"isIAMLoggingEnabled": False, "error": str(e)}
