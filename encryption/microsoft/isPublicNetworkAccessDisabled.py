# isPublicNetworkAccessDisabled.py
# Azure Key Vault - NS-2.2: Cloud Service Security - Disable Public Network Access

import json
import ast

def transform(input):
    """
    Checks whether public network access is disabled for Key Vault.
    
    API Endpoint:
        GET https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.KeyVault/vaults/{vaultName}?api-version=2023-07-01
    
    Transformation Logic:
        True if publicNetworkAccess == "Disabled" 
        OR (networkAcls.defaultAction == "Deny" AND networkAcls.ipRules is empty)
        False otherwise
    
    Returns: {"isPublicNetworkAccessDisabled": bool}
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

        # Check explicit publicNetworkAccess setting
        public_access = properties.get("publicNetworkAccess", "")
        if isinstance(public_access, str) and public_access.lower() == "disabled":
            return {"isPublicNetworkAccessDisabled": True}

        # Check networkAcls configuration
        network_acls = properties.get("networkAcls", {})
        default_action = network_acls.get("defaultAction", "Allow")
        ip_rules = network_acls.get("ipRules", [])

        if default_action == "Deny" and len(ip_rules) == 0:
            return {"isPublicNetworkAccessDisabled": True}

        return {"isPublicNetworkAccessDisabled": False}

    except json.JSONDecodeError:
        return {"isPublicNetworkAccessDisabled": False, "error": "Invalid JSON"}
    except Exception as e:
        return {"isPublicNetworkAccessDisabled": False, "error": str(e)}
