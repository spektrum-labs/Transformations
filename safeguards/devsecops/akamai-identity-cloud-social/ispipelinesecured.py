import json
import ast


def transform(input):
    """
    Evaluates isPipelineSecured for Akamai Identity Cloud Social

    Checks: Whether authentication flows are configured for identity pipeline security
    API Source: {baseURL}/config/{appId}/flows
    Pass Condition: At least one authentication flow is configured and active

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isPipelineSecured": boolean, "activeFlows": int, "totalFlows": int}
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
        flows = data.get("data", data.get("flows", data.get("results", data.get("items", []))))

        if not isinstance(flows, list):
            return {
                "isPipelineSecured": False,
                "activeFlows": 0,
                "totalFlows": 0,
                "error": "Unexpected response format"
            }

        total = len(flows)
        active = []
        for flow in flows:
            enabled = flow.get("enabled", flow.get("active", flow.get("status", "")))
            if enabled is True:
                active.append(flow)
            elif isinstance(enabled, str) and enabled.lower() in ("true", "active", "enabled"):
                active.append(flow)

        result = len(active) > 0
        # -- END EVALUATION LOGIC --

        return {
            "isPipelineSecured": result,
            "activeFlows": len(active),
            "totalFlows": total
        }

    except Exception as e:
        return {"isPipelineSecured": False, "error": str(e)}
