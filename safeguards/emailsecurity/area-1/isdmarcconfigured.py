import json
import ast


def transform(input):
    """Evaluates isDMARCConfigured for Cloudflare Area 1 (Email Security)"""
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
                    dmarc = domain.get("dmarc", domain.get("dmarcStatus", domain.get("dmarc_configured", None)))
                    if dmarc is not None:
                        if isinstance(dmarc, bool):
                            result = dmarc
                        elif isinstance(dmarc, str):
                            result = dmarc.lower() in ("pass", "enabled", "configured", "active")
                        break
        elif isinstance(domains, dict):
            dmarc = domains.get("dmarc", domains.get("dmarcStatus", None))
            if dmarc is not None:
                if isinstance(dmarc, bool):
                    result = dmarc
                elif isinstance(dmarc, str):
                    result = dmarc.lower() in ("pass", "enabled", "configured", "active")
        # ── END EVALUATION LOGIC ──

        return {"isDMARCConfigured": result}
    except Exception as e:
        return {"isDMARCConfigured": False, "error": str(e)}
