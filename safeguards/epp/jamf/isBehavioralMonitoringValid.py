import json
import ast


def transform(input):
    """
    Evaluates isBehavioralMonitoringValid for Jamf Pro (EPP)

    Checks: Whether security policies with threat prevention are active
    API Source: GET /api/v1/policies
    Pass Condition: At least one active policy relates to security, threat prevention,
                    or endpoint protection enforcement

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
        result = False
        policies = data.get("results", data.get("policies", data.get("data", [])))
        if not isinstance(policies, list):
            policies = []

        security_keywords = ["protect", "security", "threat", "malware", "gatekeeper",
                             "xprotect", "firewall", "behavioral", "detection"]
        matching = 0
        for p in policies:
            name = p.get("name", "").lower()
            enabled = p.get("enabled", p.get("isEnabled", True))
            if enabled:
                for keyword in security_keywords:
                    if keyword in name:
                        matching += 1
                        break

        if matching > 0:
            result = True
        # ── END EVALUATION LOGIC ──

        return {
            "isBehavioralMonitoringValid": result,
            "securityPolicies": matching,
            "totalPolicies": len(policies)
        }

    except Exception as e:
        return {"isBehavioralMonitoringValid": False, "error": str(e)}
