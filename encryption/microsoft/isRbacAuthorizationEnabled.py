# isRbacAuthorizationEnabled.py
# Azure Key Vault - PA-7.1: Just Enough Administration - Azure RBAC for Data Plane

import json
import ast

def transform(input):
    """
    Checks whether Azure RBAC authorization is enabled for data plane access.
    
    API Endpoint:
        GET https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.KeyVault/vaults/{vaultName}?api-version=2023-07-01
    
    Transformation Logic:
        True if properties.enableRbacAuthorization == true
        False otherwise
    
    Returns: {"isRbacAuthorizationEnabled": bool}
    """
    try:
        def _parse_input(input):
            if isinstance(input, str):
                try:
                    parsed = ast.literal_eval(input)
                    if isinstance(parsed, dict):
                        return parsed
                except:
                    pass
                try:
                    input = input.replace("'", '"')
                    return json.loads(input)
                except:
                    raise ValueError("Input string is neither valid Python literal nor JSON")
            if isinstance(input, bytes):
                return json.loads(input.decode("utf-8"))
            if isinstance(input, dict):
                return input
            raise ValueError("Input must be JSON string, bytes, or dict")

        data = _parse_input(input)
        data = data.get("response", data)
        data = data.get("result", data)
        data = data.get("apiResponse", data)
        data = data.get("data", data)

        properties = data.get("properties", {})
        rbac_enabled = properties.get("enableRbacAuthorization", False)

        is_enabled = rbac_enabled is True

        return {"isRbacAuthorizationEnabled": is_enabled}

    except json.JSONDecodeError:
        return {"isRbacAuthorizationEnabled": False, "error": "Invalid JSON"}
    except Exception as e:
        return {"isRbacAuthorizationEnabled": False, "error": str(e)}
