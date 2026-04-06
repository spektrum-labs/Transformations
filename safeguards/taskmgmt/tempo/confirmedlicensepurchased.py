import json
import ast


def transform(input):
    """
    Evaluates confirmedLicensePurchased for Tempo

    Checks: Whether the Tempo account has active accounts/subscriptions
    API Source: https://api.tempo.io/4/accounts
    Pass Condition: API returns a successful response with at least one account

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"confirmedLicensePurchased": boolean, "totalAccounts": int}
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
        results = data.get("results", data.get("data", data.get("values", [])))

        if not isinstance(results, list):
            results = [results] if isinstance(results, dict) else []

        total = len(results)
        result = total >= 1
        # -- END EVALUATION LOGIC --

        return {
            "confirmedLicensePurchased": result,
            "totalAccounts": total
        }

    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}
