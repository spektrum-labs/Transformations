# isDataAtRestEncrypted.py
# Azure Key Vault - DP-4.1: Data at Rest Encryption - Platform Keys

import json
import ast

def transform(input):
    """
    Checks whether data at rest encryption is enabled.
    Note: This is platform-enforced for Key Vault (all content encrypted).
    
    API Endpoint:
        GET https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.KeyVault/vaults/{vaultName}?api-version=2023-07-01
    
    Transformation Logic:
        True if vault exists (has valid id)
        False otherwise (encryption at rest is always enabled)
    
    Returns: {"isDataAtRestEncrypted": bool}
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

        # If the vault exists and has an ID, encryption at rest is guaranteed
        vault_id = data.get("id", "")
        is_encrypted = bool(vault_id)

        return {"isDataAtRestEncrypted": is_encrypted}

    except json.JSONDecodeError:
        return {"isDataAtRestEncrypted": False, "error": "Invalid JSON"}
    except Exception as e:
        return {"isDataAtRestEncrypted": False, "error": str(e)}
