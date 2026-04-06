import json
import ast


def transform(input):
    """
    Evaluates isRemediationTracked for PlexTrac (ASM)

    Checks: Whether finding status fields and resolution timestamps are tracked
    API Source: {baseURL}/api/v1/client/{tenantId}/reports
    Pass Condition: Reports contain findings with status or resolution data

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isRemediationTracked": boolean, "trackedReports": int, "totalReports": int}
    """
    try:
        def _parse_input(raw):
            if isinstance(raw, str):
                try:
                    parsed = ast.literal_eval(raw)
                    if isinstance(parsed, dict):
                        return parsed
                except:
                    pass
                try:
                    raw = raw.replace("'", '"')
                    return json.loads(raw)
                except:
                    raise ValueError("Input string is neither valid Python literal nor JSON")
            if isinstance(raw, bytes):
                return json.loads(raw.decode("utf-8"))
            if isinstance(raw, dict):
                return raw
            raise ValueError("Input must be JSON string, bytes, or dict")

        data = _parse_input(input)
        data = data.get("response", data)
        data = data.get("result", data)
        data = data.get("apiResponse", data)

        # ── EVALUATION LOGIC ──
        reports = data.get("data", data.get("reports", data.get("results", [])))

        if isinstance(reports, dict):
            reports = reports.get("reports", [])

        if not isinstance(reports, list):
            reports = [reports] if reports else []

        total = len(reports)
        tracked = [
            r for r in reports
            if r.get("status") or r.get("findings_count", 0) > 0
            or r.get("created_at") or r.get("updated_at")
        ]

        result = total >= 1 and len(tracked) >= 1
        # ── END EVALUATION LOGIC ──

        return {
            "isRemediationTracked": result,
            "trackedReports": len(tracked),
            "totalReports": total
        }

    except Exception as e:
        return {"isRemediationTracked": False, "error": str(e)}
