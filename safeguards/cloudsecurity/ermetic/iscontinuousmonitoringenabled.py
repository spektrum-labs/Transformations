import json
import ast


def transform(input):
    """
    Evaluates isContinuousMonitoringEnabled for Ermetic (Tenable Cloud Security)

    Checks: Whether cloud accounts are connected and actively monitored
    API Source: {baseURL}/api/v1/accounts
    Pass Condition: At least 1 connected cloud account with active monitoring

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isContinuousMonitoringEnabled": boolean, "activeAccounts": int, "totalAccounts": int}
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

        # -- EVALUATION LOGIC --
        accounts = data.get("accounts", data.get("results", data.get("data", data.get("items", []))))

        if isinstance(accounts, list):
            total = len(accounts)
            active = [
                a for a in accounts
                if str(a.get("status", "")).lower() in ("active", "connected", "enabled")
                or a.get("connected", False) is True
            ]
            result = len(active) >= 1
        elif isinstance(accounts, dict):
            total = 1
            status = str(accounts.get("status", "")).lower()
            result = status in ("active", "connected", "enabled")
            active = [accounts] if result else []
        else:
            total = 0
            active = []
            result = False
        # -- END EVALUATION LOGIC --

        return {
            "isContinuousMonitoringEnabled": result,
            "activeAccounts": len(active),
            "totalAccounts": total
        }

    except Exception as e:
        return {"isContinuousMonitoringEnabled": False, "error": str(e)}
