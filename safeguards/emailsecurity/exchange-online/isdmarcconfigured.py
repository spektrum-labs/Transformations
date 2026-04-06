import json
import ast


def transform(input):
    """Evaluates isDMARCConfigured for Exchange Online (Email Security)"""
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

        traces = data.get("value", data.get("messageTraces", []))
        if isinstance(traces, list):
            for trace in traces:
                if isinstance(trace, dict):
                    auth_details = trace.get("authenticationDetails", trace.get("authentication", {}))
                    if isinstance(auth_details, dict):
                        dmarc = auth_details.get("dmarc", auth_details.get("dmarcStatus", ""))
                        if isinstance(dmarc, str) and dmarc.lower() in ("pass", "bestguesspass"):
                            result = True
                            break
                    dmarc_status = trace.get("dmarcStatus", trace.get("dmarc", ""))
                    if isinstance(dmarc_status, str) and dmarc_status.lower() in ("pass", "bestguesspass"):
                        result = True
                        break

        settings = data.get("settings", data.get("configuration", {}))
        if isinstance(settings, dict):
            dmarc_enabled = settings.get("dmarcEnabled", settings.get("dmarc", None))
            if dmarc_enabled is not None:
                result = bool(dmarc_enabled)
        # ── END EVALUATION LOGIC ──

        return {"isDMARCConfigured": result}
    except Exception as e:
        return {"isDMARCConfigured": False, "error": str(e)}
