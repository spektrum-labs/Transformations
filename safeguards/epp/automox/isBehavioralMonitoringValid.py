import json
import ast


def transform(input):
    """
    Evaluates isBehavioralMonitoringValid for Automox (EPP)

    Checks: Whether behavioral monitoring policies are active and properly configured
    API Source: GET https://console.automox.com/api/policies?o={orgId}
    Pass Condition: Active policies exist that enforce required software or
                    custom scripts for behavioral monitoring

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isBehavioralMonitoringValid": boolean, ...metadata}
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
        # Automox uses Worklets (custom policies) and required software policies
        # to enforce security tooling. Check for active policies that indicate
        # behavioral monitoring enforcement
        result = False
        policies = data if isinstance(data, list) else data.get("results", data.get("data", []))

        if not isinstance(policies, list):
            policies = []

        active_policies = [
            p for p in policies
            if p.get("status", "").lower() == "active"
        ]

        # Automox enforces compliance through active patch and custom policies
        # Having active policies indicates the platform is being used for monitoring
        behavioral_keywords = ["monitor", "behavioral", "detection", "worklet", "custom"]
        matching = 0
        for p in active_policies:
            name = p.get("name", "").lower()
            policy_type = p.get("policy_type_name", "").lower()
            for keyword in behavioral_keywords:
                if keyword in name or keyword in policy_type:
                    matching += 1
                    break

        if matching > 0:
            result = True
        # ── END EVALUATION LOGIC ──

        return {
            "isBehavioralMonitoringValid": result,
            "matchingPolicies": matching,
            "totalActivePolicies": len(active_policies)
        }

    except Exception as e:
        return {"isBehavioralMonitoringValid": False, "error": str(e)}
