# isManagedIdentityUsed.py
# Azure Key Vault - IM-3.1: Application Identity Security - Managed Identities

import json
import ast

def transform(input):
    """
    Checks whether managed identities or service principals are configured for vault access.
    
    API Endpoints:
        - Vault: GET https://management.azure.com/.../vaults/{vaultName}?api-version=2023-07-01
        - Role Assignments (RBAC): GET https://management.azure.com/.../roleAssignments?api-version=2022-04-01
    
    Transformation Logic:
        For Access Policy vaults: True if accessPolicies contains at least one entry
        For RBAC vaults: True if roleAssignments exist or RBAC is enabled
        False otherwise
    
    Returns: {"isManagedIdentityUsed": bool}
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
        rbac_enabled = properties.get("enableRbacAuthorization", False)

        if not rbac_enabled:
            # Check access policies for any configured principals
            access_policies = properties.get("accessPolicies", [])
            if len(access_policies) > 0:
                return {"isManagedIdentityUsed": True}
        else:
            # For RBAC vaults, check role assignments if provided
            role_assignments = data.get("roleAssignments", {}).get("value", [])
            if role_assignments:
                for assignment in role_assignments:
                    principal_type = assignment.get("properties", {}).get("principalType", "")
                    if principal_type in ["ServicePrincipal", "MSI", "User", "Group"]:
                        return {"isManagedIdentityUsed": True}
            # If RBAC is enabled, assume principals are configured
            return {"isManagedIdentityUsed": True}

        return {"isManagedIdentityUsed": False}

    except json.JSONDecodeError:
        return {"isManagedIdentityUsed": False, "error": "Invalid JSON"}
    except Exception as e:
        return {"isManagedIdentityUsed": False, "error": str(e)}
