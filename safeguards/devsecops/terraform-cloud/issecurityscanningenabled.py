import json
import ast


def transform(input):
    """
    Evaluates isSecurityScanningEnabled for Terraform Cloud (HashiCorp Terraform Cloud)

    Checks: Whether workspaces are configured for infrastructure scanning
    API Source: GET https://app.terraform.io/api/v2/organizations/{organizationName}/workspaces
    Pass Condition: At least one workspace exists

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isSecurityScanningEnabled": boolean}
    """
    try:
        def _parse_input(raw):
            if isinstance(raw, str):
                try:
                    parsed = ast.literal_eval(raw)
                    if isinstance(parsed, dict):
                        return parsed
                except:
                    pass
                try:
                    raw = raw.replace("'", '"')
                    return json.loads(raw)
                except:
                    raise ValueError("Input string is neither valid Python literal nor JSON")
            if isinstance(raw, bytes):
                return json.loads(raw.decode("utf-8"))
            if isinstance(raw, dict):
                return raw
            raise ValueError("Input must be JSON string, bytes, or dict")

        data = _parse_input(input)
        data = data.get("response", data)
        data = data.get("result", data)
        data = data.get("apiResponse", data)

        # -- EVALUATION LOGIC --
        result = False

        # Check for configured workspaces
        workspaces = data.get("data", [])
        if isinstance(workspaces, list) and len(workspaces) > 0:
            result = True
        elif data.get("meta", {}).get("pagination", {}).get("total-count", 0) > 0:
            result = True
        # -- END EVALUATION LOGIC --

        return {"isSecurityScanningEnabled": result}
    except Exception as e:
        return {"isSecurityScanningEnabled": False, "error": str(e)}
