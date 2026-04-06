import json
import ast


def transform(input):
    """
    Evaluates isSecurityScanningEnabled for Dots (Payment/Payout API Platform)

    Checks: Whether transactions are being processed through the Dots platform
    API Source: GET https://api.dots.dev/api/v2/transactions
    Pass Condition: At least one transaction exists indicating active payment processing

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isSecurityScanningEnabled": boolean}
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
        result = False

        # Check for transaction records indicating active payment processing
        transactions = data.get("data", data.get("transactions", data.get("results", [])))
        if isinstance(transactions, list) and len(transactions) > 0:
            result = True
        elif isinstance(transactions, dict) and transactions.get("id"):
            result = True
        elif data.get("total", data.get("count", 0)) > 0:
            result = True
        elif data.get("has_more") is not None:
            result = True
        # -- END EVALUATION LOGIC --

        return {"isSecurityScanningEnabled": result}
    except Exception as e:
        return {"isSecurityScanningEnabled": False, "error": str(e)}
