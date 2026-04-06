import json
import ast


def transform(input):
    """
    Evaluates isContinuousDiscoveryEnabled for BloodHound Enterprise (ASM)

    Checks: Whether BloodHound collectors are active and asset groups are populated
    API Source: {baseURL}/api/v2/asset-groups
    Pass Condition: At least one asset group exists with members

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isContinuousDiscoveryEnabled": boolean, "assetGroupCount": int, "totalMembers": int}
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
        asset_groups = data.get("data", data.get("asset_groups", data.get("results", [])))

        if isinstance(asset_groups, dict):
            asset_groups = asset_groups.get("asset_groups", [])

        if not isinstance(asset_groups, list):
            return {
                "isContinuousDiscoveryEnabled": False,
                "assetGroupCount": 0,
                "totalMembers": 0,
                "error": "Unexpected asset groups response format"
            }

        group_count = len(asset_groups)
        total_members = sum(
            g.get("member_count", len(g.get("members", [])))
            for g in asset_groups
        )

        result = group_count >= 1 and total_members >= 1
        # ── END EVALUATION LOGIC ──

        return {
            "isContinuousDiscoveryEnabled": result,
            "assetGroupCount": group_count,
            "totalMembers": total_members
        }

    except Exception as e:
        return {"isContinuousDiscoveryEnabled": False, "error": str(e)}
