import json
import ast


def transform(input):
    """
    Evaluates isTicketingEnabled for WeChat Work

    Checks: Whether message statistics can be retrieved from WeChat Work
    API Source: https://qyapi.weixin.qq.com/cgi-bin/message/get_statistics
    Pass Condition: API returns errcode=0 with message data

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isTicketingEnabled": boolean, "status": str}
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

        result = errcode == 0 or bool(data.get("statistics", data.get("data", None)))
        status = "enabled" if result else "disabled"
        # -- END EVALUATION LOGIC --

        return {
            "isTicketingEnabled": result,
            "status": status
        }

    except Exception as e:
        return {"isTicketingEnabled": False, "error": str(e)}
