import json
import ast


def transform(input):
    """Evaluates isDMARCConfigured for Hoxhunt (Email Security)"""
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

        gql_data = data.get("data", data)
        org = gql_data.get("organization", gql_data)

        email_domains = org.get("emailDomains", [])
        if isinstance(email_domains, list) and len(email_domains) > 0:
            for domain in email_domains:
                if isinstance(domain, dict):
                    dmarc = domain.get("dmarc", domain.get("dmarcConfigured", None))
                    if dmarc is not None:
                        if isinstance(dmarc, bool):
                            result = dmarc
                        elif isinstance(dmarc, str):
                            result = dmarc.lower() in ("pass", "configured", "enabled")
                        break
                elif isinstance(domain, str) and len(domain) > 0:
                    result = True
                    break
        # ── END EVALUATION LOGIC ──

        return {"isDMARCConfigured": result}
    except Exception as e:
        return {"isDMARCConfigured": False, "error": str(e)}
