import json
import ast


def transform(input):
    """
    Evaluates confirmedLicensePurchased for Recorded Future

    Checks: Whether the Recorded Future account is active via the whoami endpoint
    API Source: GET https://api.recordedfuture.com/v2/info/whoami
    Pass Condition: API token is valid and returns account information

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"confirmedLicensePurchased": boolean, "accountName": str, "status": str}
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
        account = data.get("data", data)
        if isinstance(account, dict):
            company = account.get("company", account.get("name", ""))
            active = account.get("active", False)
            api_access = account.get("apiAccess", False)
        else:
            company = ""
            active = False
            api_access = False

        if isinstance(active, str):
            active = active.lower() in ("true", "1", "yes", "active")

        has_company = isinstance(company, str) and len(company.strip()) > 0
        result = bool(active) or bool(api_access) or has_company
        # -- END EVALUATION LOGIC --

        return {
            "confirmedLicensePurchased": result,
            "accountName": company,
            "status": "active" if result else "inactive"
        }

    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}
