# isFirewallEnabled.py
# Azure Key Vault - NS-2.3: Cloud Service Security - Firewall Enabled
# Azure Policy: 55615ac9-af46-4a59-874e-391cc3dfb490

import json
import ast

def transform(input):
    """
    Checks whether the Key Vault firewall is enabled (defaultAction = Deny).
    Aligns with Azure Policy: 55615ac9-af46-4a59-874e-391cc3dfb490
    
    API Endpoint:
        GET https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.KeyVault/vaults/{vaultName}?api-version=2023-07-01
    
    Transformation Logic:
        True if properties.networkAcls.defaultAction == "Deny"
        False otherwise
    
    Returns: {"isFirewallEnabled": bool}
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
        default_action = network_acls.get("defaultAction", "Allow")

        is_enabled = default_action == "Deny"

        return {"isFirewallEnabled": is_enabled}

    except json.JSONDecodeError:
        return {"isFirewallEnabled": False, "error": "Invalid JSON"}
    except Exception as e:
        return {"isFirewallEnabled": False, "error": str(e)}
