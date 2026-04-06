import json
import ast


def transform(input):
    """
    Evaluates isEPPMisconfigured for Bitdefender GravityZone (EPP)

    Checks: Whether any protection policies have critical modules disabled
    API Source: POST /api/v1.0/jsonrpc/policies (method: getPoliciesList)
    Pass Condition: Returns True if misconfiguration detected - policies with
                    antimalware or firewall modules disabled

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
        result = False
        policies = data.get("result", data)
        if isinstance(policies, dict):
            policies = policies.get("items", policies.get("data", []))
        if not isinstance(policies, list):
            policies = []

        misconfigured = 0
        for p in policies:
            settings = p.get("settings", {})
            modules = settings.get("modules", {})
            antimalware = modules.get("antimalware", {})
            firewall = modules.get("firewall", {})

            if isinstance(antimalware, dict) and not antimalware.get("enabled", True):
                misconfigured += 1
            elif isinstance(firewall, dict) and not firewall.get("enabled", True):
                misconfigured += 1

        result = misconfigured > 0
        # ── END EVALUATION LOGIC ──

        return {
            "isEPPMisconfigured": result,
            "misconfiguredPolicies": misconfigured,
            "totalPolicies": len(policies)
        }

    except Exception as e:
        return {"isEPPMisconfigured": False, "error": str(e)}
