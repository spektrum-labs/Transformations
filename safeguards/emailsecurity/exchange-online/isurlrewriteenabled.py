import json
import ast


def transform(input):
    """Evaluates isURLRewriteEnabled for Exchange Online (Email Security)"""
    try:
        def _parse_input(raw):
            if isinstance(raw, str):
                try:
                    parsed = ast.literal_eval(raw)
                    if isinstance(parsed, dict): return parsed
                except: pass
                try:
                    raw = raw.replace("'", '"')
                    return json.loads(raw)
                except: raise ValueError("Input string is neither valid Python literal nor JSON")
            if isinstance(raw, bytes): return json.loads(raw.decode("utf-8"))
            if isinstance(raw, dict): return raw
            raise ValueError("Input must be JSON string, bytes, or dict")

        data = _parse_input(input)
        data = data.get("response", data)
        data = data.get("result", data)
        data = data.get("apiResponse", data)

        # ── EVALUATION LOGIC ──
        result = False

        settings = data.get("settings", data.get("configuration", data))
        if isinstance(settings, dict):
            safe_links = settings.get("safeLinksEnabled", settings.get("safe_links", settings.get("urlRewrite", None)))
            if safe_links is not None:
                if isinstance(safe_links, bool):
                    result = safe_links
                elif isinstance(safe_links, str):
                    result = safe_links.lower() in ("enabled", "true", "active", "on")

        policies = data.get("value", [])
        if isinstance(policies, list):
            for policy in policies:
                if isinstance(policy, dict):
                    is_enabled = policy.get("isEnabled", policy.get("enabled", False))
                    if bool(is_enabled):
                        result = True
                        break
        # ── END EVALUATION LOGIC ──

        return {"isURLRewriteEnabled": result}
    except Exception as e:
        return {"isURLRewriteEnabled": False, "error": str(e)}
