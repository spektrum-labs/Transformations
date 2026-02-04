# isDiagnosticLoggingEnabled.py
# Azure Key Vault - LT-4.1: Security Investigation - Resource Logs Enabled

import json
import ast

def transform(input):
    """
    Checks whether diagnostic logging is enabled for the Key Vault.
    
    API Endpoint:
        GET https://management.azure.com/{resourceId}/providers/Microsoft.Insights/diagnosticSettings?api-version=2021-05-01-preview
    
    Transformation Logic:
        True if at least one diagnostic setting has:
          - At least one log category enabled
          - A valid destination (workspaceId, storageAccountId, or eventHubAuthorizationRuleId)
        False otherwise
    
    Returns: {"isDiagnosticLoggingEnabled": bool}
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

        # Get list of diagnostic settings
        settings = data.get("value", [])

        if len(settings) == 0:
            return {"isDiagnosticLoggingEnabled": False}

        for setting in settings:
            properties = setting.get("properties", {})
            logs = properties.get("logs", [])

            # Check if at least one log category is enabled
            has_enabled_log = False
            for log in logs:
                if log.get("enabled", False):
                    has_enabled_log = True
                    break

            if has_enabled_log:
                # Check if a destination is configured
                has_destination = (
                    properties.get("workspaceId") or
                    properties.get("storageAccountId") or
                    properties.get("eventHubAuthorizationRuleId") or
                    properties.get("eventHubName")
                )
                if has_destination:
                    return {"isDiagnosticLoggingEnabled": True}

        return {"isDiagnosticLoggingEnabled": False}

    except json.JSONDecodeError:
        return {"isDiagnosticLoggingEnabled": False, "error": "Invalid JSON"}
    except Exception as e:
        return {"isDiagnosticLoggingEnabled": False, "error": str(e)}
