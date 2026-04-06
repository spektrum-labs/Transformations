import json
import ast


def transform(input):
    """Evaluates isURLRewriteEnabled for Agari Phishing Response (Email Security)"""
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

        policy = data.get("policy", data.get("status", data))
        if isinstance(policy, dict):
            url_rewrite = policy.get("url_rewrite", policy.get("urlRewrite", policy.get("link_rewriting", None)))
            if url_rewrite is not None:
                if isinstance(url_rewrite, bool):
                    result = url_rewrite
                elif isinstance(url_rewrite, str):
                    result = url_rewrite.lower() in ("enabled", "true", "active", "on")
                elif isinstance(url_rewrite, dict):
                    result = bool(url_rewrite.get("enabled", False))
        # ── END EVALUATION LOGIC ──

        return {"isURLRewriteEnabled": result}
    except Exception as e:
        return {"isURLRewriteEnabled": False, "error": str(e)}
