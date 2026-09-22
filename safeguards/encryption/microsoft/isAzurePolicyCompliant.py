# isAzurePolicyCompliant.py
# Azure Key Vault - AM-2.1: Approved Services - Azure Policy Compliance

import json
import ast

def transform(input):
    """
    Checks whether the Key Vault is compliant with all assigned Azure Policies.
    
    API Endpoint:
        POST https://management.azure.com/{resourceId}/providers/Microsoft.PolicyInsights/policyStates/latest/queryResults?api-version=2019-10-01&$filter=complianceState eq 'NonCompliant'
    
    Transformation Logic:
        True if no non-compliant policy states exist (value array is empty)
        False if any non-compliant policies are found
    
    Returns: {"isAzurePolicyCompliant": bool}
    """
    try:
        def parse_input(input):
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

        data = parse_input(input)
        data = data.get("response", data)
        data = data.get("result", data)
        data = data.get("apiResponse", data)
        data = data.get("data", data)

        # `data.get("value", [])` defaulted to an empty LIST when the key was absent,
        # and zero non-compliant states then read as "compliant" -- so an empty object,
        # an auth-error envelope and any unrecognised body all reported compliance. The
        # `value` key must actually be present now: that is what the policyStates query
        # always returns for a real response, even an empty array.
        if not isinstance(data, dict) or "value" not in data:
            return {"isAzurePolicyCompliant": False, "error": "No policy compliance data returned"}

        non_compliant_states = data.get("value", [])
        if not isinstance(non_compliant_states, list):
            return {"isAzurePolicyCompliant": False, "error": "Unexpected 'value' shape"}

        # Also check @odata.count if present
        odata_count = data.get("@odata.count", None)
        if odata_count is not None and odata_count > 0:
            return {"isAzurePolicyCompliant": False}

        # No non-compliant states = compliant
        is_compliant = len(non_compliant_states) == 0

        return {"isAzurePolicyCompliant": is_compliant}

    except json.JSONDecodeError:
        return {"isAzurePolicyCompliant": False, "error": "Invalid JSON"}
    except Exception as e:
        return {"isAzurePolicyCompliant": False, "error": str(e)}
