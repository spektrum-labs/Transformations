import json
import ast


def transform(input):
    """Evaluates isDKIMConfigured for Cloudflare Area 1 (Email Security)"""
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
                    dkim = domain.get("dkim", domain.get("dkimStatus", domain.get("dkim_configured", None)))
                    if dkim is not None:
                        if isinstance(dkim, bool):
                            result = dkim
                        elif isinstance(dkim, str):
                            result = dkim.lower() in ("pass", "enabled", "configured", "active")
                        break
        elif isinstance(domains, dict):
            dkim = domains.get("dkim", domains.get("dkimStatus", None))
            if dkim is not None:
                if isinstance(dkim, bool):
                    result = dkim
                elif isinstance(dkim, str):
                    result = dkim.lower() in ("pass", "enabled", "configured", "active")
        # ── END EVALUATION LOGIC ──

        return {"isDKIMConfigured": result}
    except Exception as e:
        return {"isDKIMConfigured": False, "error": str(e)}
