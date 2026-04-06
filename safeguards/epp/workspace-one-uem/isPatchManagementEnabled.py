import json
import ast


def transform(input):
    """
    Evaluates isPatchManagementEnabled for Workspace ONE UEM (EPP)

    Checks: Whether OS update and patch management profiles are deployed
    API Source: GET /api/mdm/profiles/search
    Pass Condition: At least one profile related to OS updates or patches exists

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isPatchManagementEnabled": boolean, ...metadata}
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

        patch_keywords = ["update", "patch", "os update", "software update", "windows update"]
        matching = 0
        for p in profiles:
            name = p.get("ProfileName", p.get("profileName", p.get("name", ""))).lower()
            status = p.get("Status", p.get("status", "")).lower()
            for keyword in patch_keywords:
                if keyword in name:
                    if status != "inactive":
                        matching += 1
                    break

        if matching > 0:
            result = True
        # ── END EVALUATION LOGIC ──

        return {
            "isPatchManagementEnabled": result,
            "patchProfiles": matching,
            "totalProfiles": len(profiles)
        }

    except Exception as e:
        return {"isPatchManagementEnabled": False, "error": str(e)}
