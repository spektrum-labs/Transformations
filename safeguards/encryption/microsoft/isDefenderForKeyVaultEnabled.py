# isDefenderForKeyVaultEnabled.py
# Azure Key Vault - LT-1.1: Threat Detection - Microsoft Defender for Key Vault

import json
import ast

def transform(input):
    """
    Checks whether Microsoft Defender for Key Vault is enabled at the subscription level.
    
    API Endpoint:
        GET https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.Security/pricings/KeyVaults?api-version=2024-01-01
    
    Transformation Logic:
        True if properties.pricingTier == "Standard"
        False otherwise (Free tier or not configured)
    
    Returns: {"isDefenderForKeyVaultEnabled": bool}
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
        pricing_tier = properties.get("pricingTier", "Free")

        is_enabled = pricing_tier == "Standard"

        return {"isDefenderForKeyVaultEnabled": is_enabled}

    except json.JSONDecodeError:
        return {"isDefenderForKeyVaultEnabled": False, "error": "Invalid JSON"}
    except Exception as e:
        return {"isDefenderForKeyVaultEnabled": False, "error": str(e)}
