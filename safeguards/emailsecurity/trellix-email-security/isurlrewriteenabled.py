import json
import ast


def transform(input):
    """Evaluates isURLRewriteEnabled for Trellix Email Security (Email Security)"""
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

        config = data.get("config", data.get("settings", data))
        url_rewrite = config.get("urlRewrite", config.get("url_rewrite", config.get("urlClickProtection", None)))
        if url_rewrite is True:
            result = True
        elif isinstance(url_rewrite, str) and url_rewrite.lower() in ("true", "enabled", "active"):
            result = True
        elif isinstance(url_rewrite, dict):
            enabled = url_rewrite.get("enabled", url_rewrite.get("status", False))
            if enabled is True or (isinstance(enabled, str) and enabled.lower() in ("enabled", "active")):
                result = True

        if not result:
            yara_rules = config.get("urlAnalysis", config.get("url_analysis", None))
            if yara_rules is True:
                result = True
            elif isinstance(yara_rules, str) and yara_rules.lower() in ("true", "enabled"):
                result = True
        # ── END EVALUATION LOGIC ──

        return {"isURLRewriteEnabled": result}
    except Exception as e:
        return {"isURLRewriteEnabled": False, "error": str(e)}
