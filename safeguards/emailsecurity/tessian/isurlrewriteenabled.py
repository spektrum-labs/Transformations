import json
import ast


def transform(input):
    """Evaluates isURLRewriteEnabled for Tessian (Email Security)"""
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

        settings = data.get("settings", data)
        url_rewrite = settings.get("urlRewrite", settings.get("url_rewrite", settings.get("urlRewriteEnabled", None)))
        if url_rewrite is True:
            result = True
        elif isinstance(url_rewrite, str) and url_rewrite.lower() in ("true", "enabled", "active"):
            result = True
        elif isinstance(url_rewrite, dict):
            enabled = url_rewrite.get("enabled", url_rewrite.get("status", False))
            if enabled is True or (isinstance(enabled, str) and enabled.lower() in ("enabled", "active")):
                result = True

        if not result:
            link_scanning = settings.get("linkScanning", settings.get("link_scanning", None))
            if link_scanning is True:
                result = True
            elif isinstance(link_scanning, str) and link_scanning.lower() in ("true", "enabled"):
                result = True
        # ── END EVALUATION LOGIC ──

        return {"isURLRewriteEnabled": result}
    except Exception as e:
        return {"isURLRewriteEnabled": False, "error": str(e)}
