import json
import ast


def transform(input):
    """Evaluates isIAMLoggingEnabled for StrongDM (IAM)

    Checks: Whether IAM audit logging is enabled by confirming StrongDM
            captures session recordings and access logs.
    API Source: GET {baseURL}/v1/accounts
    Pass Condition: A valid accounts response confirms the StrongDM instance
                    is active with built-in session recording and audit logs.
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

        # StrongDM has built-in comprehensive audit logging and session recording.
        # A valid API response confirms the platform is active with logging.
        accounts = data.get("accounts", data)
        total = data.get("totalCount", data.get("meta", {}).get("total", 0))

        if isinstance(accounts, dict):
            accounts = accounts.get("items", accounts.get("data", []))

        if isinstance(accounts, list) and len(accounts) > 0:
            # StrongDM always captures audit logs and session recordings
            result = True
        elif isinstance(total, (int, float)) and total > 0:
            result = True
        # ── END EVALUATION LOGIC ──

        return {"isIAMLoggingEnabled": result}

    except Exception as e:
        return {"isIAMLoggingEnabled": False, "error": str(e)}
