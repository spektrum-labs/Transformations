import json
import ast


def transform(input):
    """
    Evaluates confirmedLicensePurchased for Brandsight Brand Protection

    Checks: Whether the Brandsight API returns valid account data
    API Source: GET {baseURL}/v1/account
    Pass Condition: A successful HMAC-authenticated response confirming active access

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"confirmedLicensePurchased": boolean, "status": str}
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
        error = data.get("error", data.get("errors", None))
        if error:
            return {"confirmedLicensePurchased": False, "status": "error"}

        status = data.get("status", "")
        if isinstance(status, str):
            status = status.lower()

        valid_statuses = {"active", "ok", "success"}
        result = status in valid_statuses

        if not result:
            account_id = data.get("id", data.get("account_id", ""))
            if account_id:
                result = True
                status = "active"
        # -- END EVALUATION LOGIC --

        return {
            "confirmedLicensePurchased": result,
            "status": status
        }

    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}
