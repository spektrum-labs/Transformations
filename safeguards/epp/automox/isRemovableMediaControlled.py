import json
import ast


def transform(input):
    """
    Evaluates isRemovableMediaControlled for Automox (EPP)

    Checks: Whether device control policies exist to restrict removable media
    API Source: GET https://console.automox.com/api/policies?o={orgId}
    Pass Condition: At least one active policy addresses device control or
                    required software that manages removable media restrictions

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
        # Automox policies include "custom" type policies that can enforce device control
        # Look for active policies with names or configurations related to device control
        result = False
        policies = data if isinstance(data, list) else data.get("results", data.get("data", []))

        if not isinstance(policies, list):
            policies = []

        media_keywords = ["removable", "usb", "device control", "storage", "media"]
        matching = 0
        for p in policies:
            name = p.get("name", "").lower()
            policy_type = p.get("policy_type_name", "").lower()
            status = p.get("status", "").lower()
            if status == "active":
                for keyword in media_keywords:
                    if keyword in name or keyword in policy_type:
                        matching += 1
                        break

        if matching > 0:
            result = True
        # ── END EVALUATION LOGIC ──

        return {
            "isRemovableMediaControlled": result,
            "matchingPolicies": matching,
            "totalPolicies": len(policies)
        }

    except Exception as e:
        return {"isRemovableMediaControlled": False, "error": str(e)}
