import json
import ast


def transform(input):
    """
    Evaluates isEPPMisconfigured for Workspace ONE UEM (EPP)

    Checks: Whether device profiles or compliance policies are in a failed state
    API Source: GET /api/mdm/profiles/search
    Pass Condition: Returns True if profiles have error or inactive status

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
        profiles = data.get("Profiles", data.get("profiles", data.get("data", [])))
        if not isinstance(profiles, list):
            profiles = []

        misconfigured = 0
        for p in profiles:
            status = p.get("Status", p.get("status", "")).lower()
            assigned_count = p.get("AssignedDeviceCount", p.get("assignedDeviceCount", -1))

            if status in ("error", "failed", "inactive"):
                misconfigured += 1
            elif isinstance(assigned_count, int) and assigned_count == 0 and status == "active":
                misconfigured += 1

        result = misconfigured > 0
        # ── END EVALUATION LOGIC ──

        return {
            "isEPPMisconfigured": result,
            "misconfiguredProfiles": misconfigured,
            "totalProfiles": len(profiles)
        }

    except Exception as e:
        return {"isEPPMisconfigured": False, "error": str(e)}
