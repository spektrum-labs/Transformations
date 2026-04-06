import json
import ast


def transform(input):
    """
    Evaluates isEDRDeployed for Jamf Pro (EPP)

    Checks: Whether managed devices have security features enabled
    API Source: GET /api/v1/computers-inventory
    Pass Condition: At least one computer exists with security section data indicating
                    endpoint protection is active

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isEDRDeployed": boolean, ...metadata}
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

        # ── EVALUATION LOGIC ──
        result = False
        computers = data.get("results", data.get("computers", data.get("data", [])))
        if not isinstance(computers, list):
            computers = []

        total = data.get("totalCount", len(computers))
        managed = 0
        for c in computers:
            general = c.get("general", {})
            security = c.get("security", {})
            if general.get("managed", False) or general.get("mdmCapable", {}).get("capable", False):
                managed += 1
            elif security and isinstance(security, dict) and len(security) > 0:
                managed += 1

        if total > 0 and managed > 0:
            result = True
        # ── END EVALUATION LOGIC ──

        return {
            "isEDRDeployed": result,
            "totalComputers": total,
            "managedComputers": managed
        }

    except Exception as e:
        return {"isEDRDeployed": False, "error": str(e)}
