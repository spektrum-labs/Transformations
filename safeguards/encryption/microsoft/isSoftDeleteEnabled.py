# isSoftDeleteEnabled.py
# Azure Key Vault - DP-6.1: Key Management - Soft Delete Enabled

import json
import ast

def transform(input):
    """
    Checks whether soft delete is enabled for the Key Vault.
    Note: Soft delete is enabled by default and cannot be disabled on new vaults (since Feb 2021).
    
    API Endpoint:
        GET https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.KeyVault/vaults/{vaultName}?api-version=2023-07-01
    
    Transformation Logic:
        True if properties.enableSoftDelete == true (or not present, default is true)
        False if explicitly set to false
    
    Returns: {"isSoftDeleteEnabled": bool}
    """
    try:
        def parse_input(input):
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

        data = parse_input(input)
        data = data.get("response", data)
        data = data.get("result", data)
        data = data.get("apiResponse", data)
        data = data.get("data", data)

        # An empty object, an auth-error envelope or any other body with no
        # `properties` key at all is not evidence this is even a Key Vault resource
        # response -- it must be rejected before the vendor's "absent means default
        # true" reasoning below can apply to it.
        if not isinstance(data, dict) or "properties" not in data:
            return {"isSoftDeleteEnabled": False, "error": "No Key Vault resource data returned"}

        properties = data.get("properties", {})
        if not isinstance(properties, dict):
            return {"isSoftDeleteEnabled": False, "error": "Unexpected properties shape"}

        # Default is True for new vaults (as of Feb 2021) -- but only once we know we
        # are reading an actual vault resource, per the check above.
        soft_delete_enabled = properties.get("enableSoftDelete", True)

        is_enabled = soft_delete_enabled is True

        return {"isSoftDeleteEnabled": is_enabled}

    except json.JSONDecodeError:
        return {"isSoftDeleteEnabled": False, "error": "Invalid JSON"}
    except Exception as e:
        return {"isSoftDeleteEnabled": False, "error": str(e)}
