import json
import ast


def transform(input):
    """
    Evaluates isRemovableMediaControlled for Workspace ONE UEM (EPP)

    Checks: Whether restriction profiles control USB and removable storage
    API Source: GET /api/mdm/profiles/search
    Pass Condition: At least one profile restricts removable media or USB access

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isRemovableMediaControlled": boolean, ...metadata}
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

        media_keywords = ["removable", "usb", "external", "storage", "media",
                          "restriction", "device control"]
        matching = 0
        for p in profiles:
            name = p.get("ProfileName", p.get("profileName", p.get("name", ""))).lower()
            profile_type = p.get("ProfileType", p.get("profileType", "")).lower()
            for keyword in media_keywords:
                if keyword in name or keyword in profile_type:
                    matching += 1
                    break

        if matching > 0:
            result = True
        # ── END EVALUATION LOGIC ──

        return {
            "isRemovableMediaControlled": result,
            "matchingProfiles": matching,
            "totalProfiles": len(profiles)
        }

    except Exception as e:
        return {"isRemovableMediaControlled": False, "error": str(e)}
