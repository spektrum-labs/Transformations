import json
import ast


def transform(input):
    """
    Evaluates isEPPMisconfigured for Jamf Pro (EPP)

    Checks: Whether configuration profiles or policies are in a failed state
    API Source: GET /api/v1/policies
    Pass Condition: Returns True if policies with errors or disabled state detected

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
        policies = data.get("results", data.get("policies", data.get("data", [])))
        if not isinstance(policies, list):
            policies = []

        misconfigured = 0
        for p in policies:
            enabled = p.get("enabled", p.get("isEnabled", True))
            scope = p.get("scope", {})
            has_targets = False
            if isinstance(scope, dict):
                computers = scope.get("computers", [])
                groups = scope.get("computerGroups", [])
                has_targets = (isinstance(computers, list) and len(computers) > 0) or \
                              (isinstance(groups, list) and len(groups) > 0)

            if enabled and not has_targets:
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
