# isVNetIntegrationEnabled.py
# Azure Key Vault - NS-1.1: Network Segmentation - Virtual Network Integration

import json
import ast

def transform(input):
    """
    Checks whether Virtual Network service endpoints are configured for Key Vault.
    
    API Endpoint:
        GET https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.KeyVault/vaults/{vaultName}?api-version=2023-07-01
    
    Transformation Logic:
        True if properties.networkAcls.virtualNetworkRules contains at least one entry
        False otherwise
    
    Returns: {"isVNetIntegrationEnabled": bool}
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
        network_acls = properties.get("networkAcls", {})
        vnet_rules = network_acls.get("virtualNetworkRules", [])

        is_enabled = len(vnet_rules) > 0

        return {"isVNetIntegrationEnabled": is_enabled}

    except json.JSONDecodeError:
        return {"isVNetIntegrationEnabled": False, "error": "Invalid JSON"}
    except Exception as e:
        return {"isVNetIntegrationEnabled": False, "error": str(e)}
