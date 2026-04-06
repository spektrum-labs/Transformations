import json
import ast


def transform(input):
    """Evaluates isDKIMConfigured for Exchange Online (Email Security)"""
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
                        dkim = auth_details.get("dkim", auth_details.get("dkimStatus", ""))
                        if isinstance(dkim, str) and dkim.lower() == "pass":
                            result = True
                            break
                    dkim_status = trace.get("dkimStatus", trace.get("dkim", ""))
                    if isinstance(dkim_status, str) and dkim_status.lower() == "pass":
                        result = True
                        break

        settings = data.get("settings", data.get("configuration", {}))
        if isinstance(settings, dict):
            dkim_enabled = settings.get("dkimEnabled", settings.get("dkim", None))
            if dkim_enabled is not None:
                result = bool(dkim_enabled)
        # ── END EVALUATION LOGIC ──

        return {"isDKIMConfigured": result}
    except Exception as e:
        return {"isDKIMConfigured": False, "error": str(e)}
