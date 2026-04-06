import json
import ast


def transform(input):
    """
    Evaluates isThreatIntelIntegrated for Ghostwriter (ASM)

    Checks: Whether recent oplog entries show active tool output and operator activity
    API Source: {baseURL}/v1/graphql (oplogEntry query)
    Pass Condition: At least one recent oplog entry exists with tool output

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isThreatIntelIntegrated": boolean, "recentEntries": int, "entriesWithOutput": int}
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
        gql_data = data.get("data", data)
        entries = gql_data.get("oplogEntry", gql_data.get("oplog_entries", []))

        if not isinstance(entries, list):
            entries = [entries] if entries else []

        recent_count = len(entries)
        with_output = [
            e for e in entries
            if e.get("output") or e.get("tool") or e.get("comments")
        ]

        result = recent_count >= 1 and len(with_output) >= 1
        # ── END EVALUATION LOGIC ──

        return {
            "isThreatIntelIntegrated": result,
            "recentEntries": recent_count,
            "entriesWithOutput": len(with_output)
        }

    except Exception as e:
        return {"isThreatIntelIntegrated": False, "error": str(e)}
