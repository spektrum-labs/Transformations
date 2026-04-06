import json
import ast


def transform(input):
    """Evaluates isURLRewriteEnabled for Hoxhunt (Email Security)"""
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

        sim_settings = org.get("simulationSettings", {})
        if isinstance(sim_settings, dict):
            enabled = sim_settings.get("enabled", False)
            result = bool(enabled)

            url_tracking = sim_settings.get("urlTracking", sim_settings.get("linkTracking", None))
            if url_tracking is not None:
                result = bool(url_tracking)
        # ── END EVALUATION LOGIC ──

        return {"isURLRewriteEnabled": result}
    except Exception as e:
        return {"isURLRewriteEnabled": False, "error": str(e)}
