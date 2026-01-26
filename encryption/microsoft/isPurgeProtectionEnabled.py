# isPurgeProtectionEnabled.py
# Azure Key Vault - DP-6.2: Key Management - Purge Protection Enabled

import json
import ast

def transform(input):
    """
    Checks whether purge protection is enabled for the Key Vault.
    Note: Once enabled, purge protection cannot be disabled.
    
    API Endpoint:
        GET https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.KeyVault/vaults/{vaultName}?api-version=2023-07-01
    
    Transformation Logic:
        True if properties.enablePurgeProtection == true
        False otherwise
    
    Returns: {"isPurgeProtectionEnabled": bool}
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
        purge_protection_enabled = properties.get("enablePurgeProtection", False)

        is_enabled = purge_protection_enabled is True

        return {"isPurgeProtectionEnabled": is_enabled}

    except json.JSONDecodeError:
        return {"isPurgeProtectionEnabled": False, "error": "Invalid JSON"}
    except Exception as e:
        return {"isPurgeProtectionEnabled": False, "error": str(e)}
