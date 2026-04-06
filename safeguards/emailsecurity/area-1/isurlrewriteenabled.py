import json
import ast


def transform(input):
    """Evaluates isURLRewriteEnabled for Cloudflare Area 1 (Email Security)"""
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

        domains = data.get("result", data.get("domains", []))
        if isinstance(domains, list):
            for domain in domains:
                if isinstance(domain, dict):
                    url_rewrite = domain.get("link_isolation", domain.get("urlRewrite", domain.get("browser_isolation", None)))
                    if url_rewrite is not None:
                        if isinstance(url_rewrite, bool):
                            result = url_rewrite
                        elif isinstance(url_rewrite, str):
                            result = url_rewrite.lower() in ("enabled", "true", "active", "on")
                        break
        elif isinstance(domains, dict):
            url_rewrite = domains.get("link_isolation", domains.get("urlRewrite", None))
            if url_rewrite is not None:
                if isinstance(url_rewrite, bool):
                    result = url_rewrite
                elif isinstance(url_rewrite, str):
                    result = url_rewrite.lower() in ("enabled", "true", "active", "on")
        # ── END EVALUATION LOGIC ──

        return {"isURLRewriteEnabled": result}
    except Exception as e:
        return {"isURLRewriteEnabled": False, "error": str(e)}
