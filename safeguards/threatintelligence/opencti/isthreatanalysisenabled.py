import json
import ast


def transform(input):
    """
    Evaluates isThreatAnalysisEnabled for OpenCTI.

    Checks: Threat intelligence reports are accessible via the GraphQL reports query.
    API Source: POST {baseURL}/graphql (query: reports)
    Pass Condition: Response contains report edges with at least one node.

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isThreatAnalysisEnabled": boolean}
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

        # Check for GraphQL reports data
        gql_data = data.get("data", data)
        if isinstance(gql_data, dict):
            reports = gql_data.get("reports", {})
            if isinstance(reports, dict):
                edges = reports.get("edges", [])
                if isinstance(edges, list) and len(edges) > 0:
                    return {"isThreatAnalysisEnabled": True}

                page_info = reports.get("pageInfo", {})
                if isinstance(page_info, dict):
                    global_count = page_info.get("globalCount", 0)
                    if isinstance(global_count, int) and global_count > 0:
                        return {"isThreatAnalysisEnabled": True}

        if isinstance(data, dict) and len(data) > 0 and "errors" not in data and "error" not in data:
            result = True
        else:
            result = False

        return {"isThreatAnalysisEnabled": result}

    except Exception as e:
        return {"isThreatAnalysisEnabled": False, "error": str(e)}
