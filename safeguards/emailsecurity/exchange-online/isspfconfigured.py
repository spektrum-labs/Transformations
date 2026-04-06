import json
import ast


def transform(input):
    """Evaluates isSPFConfigured for Exchange Online (Email Security)"""
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
                        spf = auth_details.get("spf", auth_details.get("spfStatus", ""))
                        if isinstance(spf, str) and spf.lower() == "pass":
                            result = True
                            break
                    spf_status = trace.get("spfStatus", trace.get("spf", ""))
                    if isinstance(spf_status, str) and spf_status.lower() == "pass":
                        result = True
                        break

        settings = data.get("settings", data.get("configuration", {}))
        if isinstance(settings, dict):
            spf_enabled = settings.get("spfEnabled", settings.get("spf", None))
            if spf_enabled is not None:
                result = bool(spf_enabled)
        # ── END EVALUATION LOGIC ──

        return {"isSPFConfigured": result}
    except Exception as e:
        return {"isSPFConfigured": False, "error": str(e)}
