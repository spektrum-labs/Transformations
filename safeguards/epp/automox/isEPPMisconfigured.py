import json
import ast


def transform(input):
    """
    Evaluates isEPPMisconfigured for Automox (EPP)

    Checks: Whether any Automox policies are in an error or misconfigured state
    API Source: GET https://console.automox.com/api/policies?o={orgId}
    Pass Condition: No policies are found with error status or zero server count
                    while marked as active (returns True if misconfiguration found)

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isEPPMisconfigured": boolean, ...metadata}
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
        # Check for misconfigured policies: active policies with no servers assigned
        # or policies in error state
        result = False
        policies = data if isinstance(data, list) else data.get("results", data.get("data", []))

        if not isinstance(policies, list):
            policies = []

        misconfigured = 0
        for p in policies:
            status = p.get("status", "").lower()
            server_count = p.get("server_count", 0)
            if status == "active" and (server_count is None or server_count == 0):
                misconfigured += 1

        # isEPPMisconfigured = True means there IS a misconfiguration (bad)
        result = misconfigured > 0
        # ── END EVALUATION LOGIC ──

        return {
            "isEPPMisconfigured": result,
            "misconfiguredPolicies": misconfigured,
            "totalPolicies": len(policies)
        }

    except Exception as e:
        return {"isEPPMisconfigured": False, "error": str(e)}
