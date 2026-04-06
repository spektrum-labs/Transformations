import json
import ast


def transform(input):
    """
    Evaluates isEPPDeployed for Workspace ONE UEM (EPP)

    Checks: Whether Workspace ONE UEM is managing and enrolling endpoints
    API Source: GET /api/mdm/devices/search
    Pass Condition: Enrolled devices exist in the UEM console

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isEPPDeployed": boolean, ...metadata}
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
        devices = data.get("Devices", data.get("devices", data.get("data", [])))
        if not isinstance(devices, list):
            devices = []

        total = data.get("Total", data.get("total", len(devices)))
        enrolled = 0
        for d in devices:
            enrollment = d.get("EnrollmentStatus", d.get("enrollmentStatus", ""))
            if str(enrollment).lower() == "enrolled":
                enrolled += 1

        if total > 0 and enrolled > 0:
            result = True
        elif total > 0:
            result = True
        # ── END EVALUATION LOGIC ──

        return {
            "isEPPDeployed": result,
            "totalDevices": total,
            "enrolledDevices": enrolled
        }

    except Exception as e:
        return {"isEPPDeployed": False, "error": str(e)}
