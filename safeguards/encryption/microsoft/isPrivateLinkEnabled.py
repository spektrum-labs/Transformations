# isPrivateLinkEnabled.py
# Azure Key Vault - NS-2.1: Cloud Service Security - Azure Private Link

import json
import ast

def transform(input):
    """
    Checks whether Private Endpoints are configured and approved for Key Vault.
    
    API Endpoint:
        GET https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.KeyVault/vaults/{vaultName}/privateEndpointConnections?api-version=2023-07-01
    
    Transformation Logic:
        True if at least one connection has privateLinkServiceConnectionState.status == "Approved"
        False otherwise
    
    Returns: {"isPrivateLinkEnabled": bool}
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

        # Get list of private endpoint connections
        connections = data.get("value", [])
        
        # If data itself is the vault response, check for embedded connections
        if not connections and "properties" in data:
            connections = data.get("properties", {}).get("privateEndpointConnections", [])

        for conn in connections:
            props = conn.get("properties", {})
            state = props.get("privateLinkServiceConnectionState", {})
            if state.get("status") == "Approved":
                return {"isPrivateLinkEnabled": True}

        return {"isPrivateLinkEnabled": False}

    except json.JSONDecodeError:
        return {"isPrivateLinkEnabled": False, "error": "Invalid JSON"}
    except Exception as e:
        return {"isPrivateLinkEnabled": False, "error": str(e)}
