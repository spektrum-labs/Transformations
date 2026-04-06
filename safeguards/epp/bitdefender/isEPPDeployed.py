import json
import ast


def transform(input):
    """
    Evaluates isEPPDeployed for Bitdefender GravityZone (EPP)

    Checks: Whether Bitdefender endpoint protection agents are deployed
    API Source: POST /api/v1.0/jsonrpc/network (method: getEndpointsList)
    Pass Condition: Managed endpoints exist and are reporting to GravityZone

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isEPPDeployed": boolean, ...metadata}
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
        items = data.get("result", data)
        if isinstance(items, dict):
            items = items.get("items", items.get("data", []))
            total_count = data.get("result", {}).get("total", 0) if isinstance(data.get("result"), dict) else 0
        else:
            total_count = 0

        if not isinstance(items, list):
            items = []

        total = len(items) if len(items) > 0 else total_count
        managed = sum(1 for ep in items if ep.get("isManaged", True))

        if total > 0 and managed > 0:
            result = True
        # ── END EVALUATION LOGIC ──

        return {
            "isEPPDeployed": result,
            "totalEndpoints": total,
            "managedEndpoints": managed
        }

    except Exception as e:
        return {"isEPPDeployed": False, "error": str(e)}
