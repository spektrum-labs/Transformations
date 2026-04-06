import json
import ast


def transform(input):
    """
    Evaluates isBehavioralMonitoringValid for Workspace ONE UEM (EPP)

    Checks: Whether compliance policies with behavioral rules and automated actions exist
    API Source: GET /api/mdm/profiles/search
    Pass Condition: At least one compliance or security profile with enforcement is active

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
        profiles = data.get("Profiles", data.get("profiles", data.get("data", [])))
        if not isinstance(profiles, list):
            profiles = []

        security_keywords = ["compliance", "security", "protection", "antivirus",
                             "firewall", "threat", "detection", "monitor", "behavioral"]
        matching = 0
        for p in profiles:
            name = p.get("ProfileName", p.get("profileName", p.get("name", ""))).lower()
            status = p.get("Status", p.get("status", "")).lower()
            if status not in ("inactive", "error"):
                for keyword in security_keywords:
                    if keyword in name:
                        matching += 1
                        break

        if matching > 0:
            result = True
        # ── END EVALUATION LOGIC ──

        return {
            "isBehavioralMonitoringValid": result,
            "securityProfiles": matching,
            "totalProfiles": len(profiles)
        }

    except Exception as e:
        return {"isBehavioralMonitoringValid": False, "error": str(e)}
