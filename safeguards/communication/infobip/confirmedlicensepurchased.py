import json
import ast


def transform(input):
    """
    Evaluates confirmedLicensePurchased for Infobip

    Checks: Whether the Infobip account is active
    API Source: {baseURL}/settings/1/accounts/current
    Pass Condition: Account status is 'ACTIVE' or account is enabled

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"confirmedLicensePurchased": boolean, "status": str, "accountName": str}
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
        status = data.get("status", "")
        active = data.get("active", data.get("enabled", False))
        account_name = data.get("accountName", data.get("name", "unknown"))

        if isinstance(status, str):
            status = status.lower()

        valid_statuses = {"active", "enabled", "trial"}
        result = status in valid_statuses or active is True
        # -- END EVALUATION LOGIC --

        return {
            "confirmedLicensePurchased": result,
            "status": status,
            "accountName": account_name
        }

    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}
