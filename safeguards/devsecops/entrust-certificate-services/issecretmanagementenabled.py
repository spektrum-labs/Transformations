import json
import ast


def transform(input):
    """
    Evaluates isSecretManagementEnabled for Entrust Certificate Services (PKI / Certificate Management)

    Checks: Whether the Entrust account is operational with active certificate management
    API Source: GET https://api.managed.entrust.com/v1/accounts
    Pass Condition: Account status indicates active PKI infrastructure

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isSecretManagementEnabled": boolean}
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

        # Check if the Entrust account has active PKI management
        accounts = data.get("accounts", data.get("data", data))
        if isinstance(accounts, list) and len(accounts) > 0:
            result = True
        elif isinstance(accounts, dict):
            if accounts.get("id") or accounts.get("organizationName"):
                result = True
            elif accounts.get("status") and str(accounts.get("status")).lower() != "inactive":
                result = True
        elif isinstance(data, dict) and len(data) > 0 and not data.get("error"):
            result = True
        # -- END EVALUATION LOGIC --

        return {"isSecretManagementEnabled": result}
    except Exception as e:
        return {"isSecretManagementEnabled": False, "error": str(e)}
