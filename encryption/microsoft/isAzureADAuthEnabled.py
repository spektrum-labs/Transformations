# isAzureADAuthEnabled.py
# Azure Key Vault - IM-1.1: Centralized Identity - Azure AD Authentication

import json
import ast

def transform(input):
    """
    Checks whether Azure AD authentication is enabled for Key Vault.
    Note: This is platform-enforced - Key Vault always requires Azure AD.
    
    API Endpoint:
        GET https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.KeyVault/vaults/{vaultName}?api-version=2023-07-01
    
    Transformation Logic:
        True if properties.tenantId exists and is not empty
        False otherwise (should never occur for valid vaults)
    
    Returns: {"isAzureADAuthEnabled": bool}
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
        tenant_id = properties.get("tenantId", "")

        # Azure AD is always required - vault won't exist without tenantId
        is_enabled = bool(tenant_id)

        return {"isAzureADAuthEnabled": is_enabled}

    except json.JSONDecodeError:
        return {"isAzureADAuthEnabled": False, "error": "Invalid JSON"}
    except Exception as e:
        return {"isAzureADAuthEnabled": False, "error": str(e)}
