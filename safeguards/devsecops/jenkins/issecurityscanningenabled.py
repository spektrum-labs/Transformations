import json
import ast


def transform(input):
    """
    Evaluates isSecurityScanningEnabled for Jenkins

    Checks: Whether security scanning jobs are configured and producing results
    API Source: {baseURL}/api/json?tree=jobs[name,lastBuild[result,actions[totalCount,failCount,skipCount]]]
    Pass Condition: At least one job with a successful last build and test results exists

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isSecurityScanningEnabled": boolean, "totalJobs": int, "jobsWithScans": int}
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
        jobs = data.get("jobs", [])

        if not isinstance(jobs, list):
            return {
                "isSecurityScanningEnabled": False,
                "totalJobs": 0,
                "jobsWithScans": 0,
                "error": "Unexpected response format"
            }

        total = len(jobs)
        jobs_with_scans = [
            j for j in jobs
            if isinstance(j, dict)
            and j.get("lastBuild")
            and isinstance(j["lastBuild"], dict)
            and j["lastBuild"].get("result") in ("SUCCESS", "UNSTABLE")
        ]

        result = len(jobs_with_scans) >= 1
        # -- END EVALUATION LOGIC --

        return {
            "isSecurityScanningEnabled": result,
            "totalJobs": total,
            "jobsWithScans": len(jobs_with_scans)
        }

    except Exception as e:
        return {"isSecurityScanningEnabled": False, "error": str(e)}
