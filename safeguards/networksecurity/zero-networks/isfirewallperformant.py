import json
import ast


def transform(input):
    """Evaluates isFirewallPerformant for Zero Networks (Network Security)"""
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
                    raise ValueError("Invalid input")
            if isinstance(raw, bytes):
                return json.loads(raw.decode("utf-8"))
            if isinstance(raw, dict):
                return raw
            raise ValueError("Input must be JSON string, bytes, or dict")

        data = _parse_input(input)
        data = data.get("response", data)
        data = data.get("result", data)
        data = data.get("apiResponse", data)

        # -- EVALUATION LOGIC --
        result = False

        # Zero Networks is SaaS; asset data confirms healthy segmentation enforcement
        items = data.get("items", data.get("assets", []))
        if isinstance(items, list) and len(items) > 0:
            protected = 0
            total = len(items)
            for asset in items:
                if isinstance(asset, dict):
                    state = asset.get("protectionState", asset.get("state", 0))
                    if state and str(state) != "0":
                        protected += 1
            if total > 0 and protected > 0:
                result = True
        elif isinstance(data, dict) and data.get("status", "").lower() in ("ok", "healthy", "active"):
            result = True

        # -- END EVALUATION LOGIC --

        return {"isFirewallPerformant": result}

    except Exception as e:
        return {"isFirewallPerformant": False, "error": str(e)}
