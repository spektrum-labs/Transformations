import json
import ast


def transform(input):
    """
    Evaluates isIntegrationHealthy for WeChat Work

    Checks: Whether the WeChat Work API is responding with valid agent data
    API Source: https://qyapi.weixin.qq.com/cgi-bin/agent/get
    Pass Condition: API returns errcode=0

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isIntegrationHealthy": boolean, "errcode": int, "errmsg": str}
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
        errcode = data.get("errcode", -1)
        errmsg = data.get("errmsg", "")

        result = errcode == 0
        # -- END EVALUATION LOGIC --

        return {
            "isIntegrationHealthy": result,
            "errcode": errcode,
            "errmsg": errmsg
        }

    except Exception as e:
        return {"isIntegrationHealthy": False, "error": str(e)}
