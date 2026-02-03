# isDataInTransitEncrypted.py
# Azure Key Vault - DP-3.1: Data in Transit Encryption - TLS

import json
import ast

def transform(input):
    """
    Checks whether data in transit encryption is enabled (TLS).
    Note: This is platform-enforced for Key Vault (always TLS 1.2+).
    
    API Endpoint:
        GET https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.KeyVault/vaults/{vaultName}?api-version=2023-07-01
    
    Transformation Logic:
        True if properties.vaultUri starts with "https://"
        False otherwise (should never occur for valid vaults)
    
    Returns: {"isDataInTransitEncrypted": bool}
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
        vault_uri = properties.get("vaultUri", "")

        # Key Vault always uses HTTPS - platform enforced
        is_encrypted = vault_uri.startswith("https://")

        return {"isDataInTransitEncrypted": is_encrypted}

    except json.JSONDecodeError:
        return {"isDataInTransitEncrypted": False, "error": "Invalid JSON"}
    except Exception as e:
        return {"isDataInTransitEncrypted": False, "error": str(e)}
