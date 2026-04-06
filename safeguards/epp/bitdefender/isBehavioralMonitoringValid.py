import json
import ast


def transform(input):
    """
    Evaluates isBehavioralMonitoringValid for Bitdefender GravityZone (EPP)

    Checks: Whether Advanced Threat Control (ATC) behavioral monitoring is enabled
    API Source: POST /api/v1.0/jsonrpc/policies (method: getPoliciesList)
    Pass Condition: At least one policy has ATC or HyperDetect modules enabled

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
        policies = data.get("result", data)
        if isinstance(policies, dict):
            policies = policies.get("items", policies.get("data", []))
        if not isinstance(policies, list):
            policies = []

        behavioral_count = 0
        for p in policies:
            settings = p.get("settings", {})
            modules = settings.get("modules", {})
            atc = modules.get("advancedThreatControl", modules.get("atc", {}))
            hyperdetect = modules.get("hyperDetect", modules.get("hyperdetect", {}))

            if isinstance(atc, dict) and atc.get("enabled", False):
                behavioral_count += 1
            elif isinstance(hyperdetect, dict) and hyperdetect.get("enabled", False):
                behavioral_count += 1

        if behavioral_count > 0:
            result = True
        # ── END EVALUATION LOGIC ──

        return {
            "isBehavioralMonitoringValid": result,
            "behavioralMonitoringPolicies": behavioral_count,
            "totalPolicies": len(policies)
        }

    except Exception as e:
        return {"isBehavioralMonitoringValid": False, "error": str(e)}
