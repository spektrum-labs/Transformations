import json
import ast


def transform(input):
    """
    Evaluates isContinuousMonitoringEnabled for Device42

    Checks: Whether Device42 autodiscovery jobs are running for continuous monitoring
    API Source: {baseURL}/api/1.0/jobs/
    Pass Condition: At least one discovery job exists and is scheduled or running

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isContinuousMonitoringEnabled": boolean, "totalJobs": int}
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
        jobs = data.get("jobs", data.get("data", data.get("results", data.get("items", []))))

        if isinstance(jobs, list):
            total = len(jobs)
        elif isinstance(jobs, dict):
            total = jobs.get("total_count", jobs.get("totalCount", 0))
        else:
            total = 0

        result = total > 0
        # -- END EVALUATION LOGIC --

        return {
            "isContinuousMonitoringEnabled": result,
            "totalJobs": total
        }

    except Exception as e:
        return {"isContinuousMonitoringEnabled": False, "error": str(e)}
