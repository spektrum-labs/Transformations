import json
import ast


def transform(input):
    """Evaluates isAntiPhishingEnabled for Hoxhunt (Email Security)"""
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
        incidents = gql_data.get("incidents", {})

        if isinstance(incidents, dict):
            edges = incidents.get("edges", [])
            if isinstance(edges, list) and len(edges) > 0:
                result = True
        elif isinstance(incidents, list) and len(incidents) > 0:
            result = True

        sim_settings = gql_data.get("organization", {}).get("simulationSettings", {})
        if isinstance(sim_settings, dict):
            enabled = sim_settings.get("enabled", None)
            if enabled is not None:
                result = bool(enabled)
        # ── END EVALUATION LOGIC ──

        return {"isAntiPhishingEnabled": result}
    except Exception as e:
        return {"isAntiPhishingEnabled": False, "error": str(e)}
