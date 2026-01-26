# keysHaveExpirationDate.py
# Azure Key Vault - DP-6.3: Key Management - Key Expiration Dates
# Azure Policy: 152b15f7-8e1f-4c1f-ab71-8c010ba5dbc0

import json
import ast

def transform(input):
    """
    Checks whether all keys have expiration dates set.
    Aligns with Azure Policy: 152b15f7-8e1f-4c1f-ab71-8c010ba5dbc0
    
    API Endpoint (Data Plane):
        GET https://{vaultName}.vault.azure.net/keys?api-version=7.4
        Token scope: https://vault.azure.net/.default
    
    Transformation Logic:
        True if all keys have attributes.exp set (or no keys exist)
        False if any key is missing expiration date
    
    Returns: {"keysHaveExpirationDate": bool}
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

        # Get list of keys
        keys = data.get("value", [])

        # If no keys exist, consider compliant
        if len(keys) == 0:
            return {"keysHaveExpirationDate": True}

        # Check each key for expiration attribute
        for key in keys:
            attributes = key.get("attributes", {})
            expiration = attributes.get("exp")
            
            if expiration is None:
                return {"keysHaveExpirationDate": False}

        return {"keysHaveExpirationDate": True}

    except json.JSONDecodeError:
        return {"keysHaveExpirationDate": False, "error": "Invalid JSON"}
    except Exception as e:
        return {"keysHaveExpirationDate": False, "error": str(e)}
