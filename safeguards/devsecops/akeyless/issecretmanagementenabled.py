import json
import ast


def transform(input):
    """
    Evaluates isSecretManagementEnabled for Akeyless

    Checks: Whether secrets are stored and managed in the Akeyless vault
    API Source: {baseURL}/list-items
    Pass Condition: Vault contains at least one managed secret item

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isSecretManagementEnabled": boolean, "managedSecrets": int}
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
        items = data.get("items", data.get("data", data.get("results", data.get("secrets", []))))

        if isinstance(items, list):
            managed = len(items)
            result = managed > 0
        elif isinstance(items, dict):
            managed = items.get("totalCount", items.get("total", 0))
            result = managed > 0
        else:
            managed = 0
            result = False
        # -- END EVALUATION LOGIC --

        return {
            "isSecretManagementEnabled": result,
            "managedSecrets": managed
        }

    except Exception as e:
        return {"isSecretManagementEnabled": False, "error": str(e)}
