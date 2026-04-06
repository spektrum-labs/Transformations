import json
import ast


def transform(input):
    """
    Evaluates isLogIngestionActive for Elasticsearch

    Checks: Whether log data stream indices exist and are receiving data
    API Source: /_cat/indices/.ds-logs-*?format=json
    Pass Condition: At least one log index exists with documents

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isLogIngestionActive": boolean, "indexCount": int, "totalDocs": int}
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

        # -- EVALUATION LOGIC --
        indices = data if isinstance(data, list) else data.get("indices", data.get("data", []))
        if not isinstance(indices, list):
            return {
                "isLogIngestionActive": False,
                "indexCount": 0,
                "totalDocs": 0,
                "error": "Unexpected indices response format"
            }

        index_count = len(indices)
        total_docs = 0
        for idx in indices:
            doc_count = idx.get("docs.count", idx.get("docsCount", "0"))
            try:
                total_docs = total_docs + int(doc_count)
            except (ValueError, TypeError):
                pass

        result = index_count >= 1 and total_docs > 0
        # -- END EVALUATION LOGIC --

        return {
            "isLogIngestionActive": result,
            "indexCount": index_count,
            "totalDocs": total_docs
        }

    except Exception as e:
        return {"isLogIngestionActive": False, "error": str(e)}
