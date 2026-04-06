import json
import ast


def transform(input):
    """
    Evaluates isEDRDeployed for Bitdefender GravityZone (EPP)

    Checks: Whether EDR modules are active on managed endpoints
    API Source: POST /api/v1.0/jsonrpc/network (method: getEndpointsList)
    Pass Condition: At least one managed endpoint exists with protection modules active

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
        # GravityZone getEndpointsList returns items with modules info
        result = False
        items = data.get("result", data)
        if isinstance(items, dict):
            items = items.get("items", items.get("data", []))
        if not isinstance(items, list):
            items = []

        total = len(items)
        managed = 0
        for ep in items:
            modules = ep.get("modules", {})
            if isinstance(modules, dict) and len(modules) > 0:
                managed += 1
            elif ep.get("isManaged", False):
                managed += 1

        if total > 0 and managed > 0:
            result = True
        # ── END EVALUATION LOGIC ──

        return {
            "isEDRDeployed": result,
            "totalEndpoints": total,
            "managedEndpoints": managed
        }

    except Exception as e:
        return {"isEDRDeployed": False, "error": str(e)}
