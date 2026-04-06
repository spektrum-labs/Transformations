import json
import ast


def transform(input):
    """Evaluates isEmailLoggingEnabled for Exchange Online (Email Security)"""
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
        if isinstance(traces, list) and len(traces) > 0:
            result = True

        audit = data.get("auditEnabled", data.get("mailboxAuditEnabled", None))
        if audit is not None:
            result = bool(audit)
        # ── END EVALUATION LOGIC ──

        return {"isEmailLoggingEnabled": result}
    except Exception as e:
        return {"isEmailLoggingEnabled": False, "error": str(e)}
