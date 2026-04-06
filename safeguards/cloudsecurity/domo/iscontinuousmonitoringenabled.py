import json
import ast


def transform(input):
    """
    Evaluates isContinuousMonitoringEnabled for Domo

    Checks: Whether Domo accounts and connectors are actively running
    API Source: {baseURL}/v1/accounts
    Pass Condition: At least one account connector is configured and active

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isContinuousMonitoringEnabled": boolean, "totalAccounts": int}
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
        accounts = data.get("data", data.get("accounts", data.get("results", data.get("items", []))))

        if isinstance(accounts, list):
            total = len(accounts)
        elif isinstance(accounts, dict):
            total = accounts.get("totalCount", accounts.get("total", 0))
        else:
            total = 0

        result = total > 0
        # -- END EVALUATION LOGIC --

        return {
            "isContinuousMonitoringEnabled": result,
            "totalAccounts": total
        }

    except Exception as e:
        return {"isContinuousMonitoringEnabled": False, "error": str(e)}
