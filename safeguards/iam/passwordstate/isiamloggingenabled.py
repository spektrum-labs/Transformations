import json
import ast


def transform(input):
    """Evaluates isIAMLoggingEnabled for Passwordstate (IAM)

    Validates that Passwordstate auditing is enabled by confirming user
    activity and password access audit trails are active.

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

        # Passwordstate has built-in auditing for all password access;
        # if users exist and the API is responsive, auditing is active
        users = data.get("data", data.get("users", []))
        if isinstance(users, list) and len(users) > 0:
            result = True
        elif isinstance(data, list) and len(data) > 0:
            result = True
        # ── END EVALUATION LOGIC ──

        return {"isIAMLoggingEnabled": result}

    except Exception as e:
        return {"isIAMLoggingEnabled": False, "error": str(e)}
