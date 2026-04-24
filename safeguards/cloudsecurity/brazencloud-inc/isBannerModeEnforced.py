"""
Transformation: isBannerModeEnforced
Vendor: BrazenCloud, Inc.  |  Category: cloudsecurity
Evaluates: Whether banner mode enforcement policies are active in the connected cloud
           environment, based on BrazenCloud job execution results (getJobResults).
"""
import json
from datetime import datetime


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for i in range(3):
            unwrapped = False
            for key in wrapper_keys:
                if key in data and isinstance(data.get(key), dict):
                    data = data[key]
                    unwrapped = True
                    break
            if not unwrapped:
                break
    return data, {"status": "unknown", "errors": [], "warnings": ["Legacy input format"]}


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, transformation_errors=None,
                    api_errors=None, additional_findings=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {
                "status": "error" if (api_errors or []) else "success",
                "errors": api_errors or []
            },
            "validation": {
                "status": validation.get("status", "unknown"),
                "errors": validation.get("errors", []),
                "warnings": validation.get("warnings", [])
            },
            "transformation": {
                "status": "error" if (transformation_errors or []) else "success",
                "errors": transformation_errors or [],
                "inputSummary": input_summary or {}
            },
            "evaluation": {
                "passReasons": pass_reasons or [],
                "failReasons": fail_reasons or [],
                "recommendations": recommendations or [],
                "additionalFindings": additional_findings or []
            },
            "metadata": {
                "evaluatedAt": datetime.utcnow().isoformat() + "Z",
                "schemaVersion": "1.0",
                "transformationId": "isBannerModeEnforced",
                "vendor": "BrazenCloud, Inc.",
                "category": "cloudsecurity"
            }
        }
    }


def to_searchable(val):
    if isinstance(val, str):
        return val.lower()
    if isinstance(val, (dict, list)):
        try:
            return json.dumps(val).lower()
        except Exception:
            return str(val).lower()
    return str(val).lower()


def extract_job_results(data):
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        candidates = ["data", "results", "items", "jobResults"]
        for key in candidates:
            val = data.get(key)
            if isinstance(val, list):
                return val
    return []


def evaluate(data):
    try:
        job_results = extract_job_results(data)
        total_results = len(job_results)

        if total_results == 0:
            return {
                "isBannerModeEnforced": False,
                "totalJobResults": 0,
                "enforcedEvidenceCount": 0,
                "notEnforcedEvidenceCount": 0,
                "evaluationNote": "No job results available to evaluate banner mode enforcement state"
            }

        enforced_keywords = [
            "bannermode", "bannerenforced", "bannerpolicy", "bannerenabled",
            "loginbanner", "banneractive", "warningbanner", "legalnotice",
            "legalnoticecaption", "legalnoticetext", "interactivelogon",
            "displaylogonbanner", "motd"
        ]
        not_enforced_keywords = [
            "bannerdisabled", "bannernotset", "nobannermode",
            "bannernotconfigured", "bannermodeoff"
        ]

        enforced_evidence = []
        not_enforced_evidence = []
        output_fields = ["output", "data", "result", "stdout", "value", "content",
                         "response", "actionOutput", "jobOutput", "text"]

        for item in job_results:
            if not isinstance(item, dict):
                continue

            searchable_parts = []
            for field in output_fields:
                val = item.get(field)
                if val is not None:
                    searchable_parts.append(to_searchable(val))
            searchable_parts.append(to_searchable(item))
            combined_text = " ".join(searchable_parts)

            pos_found = False
            neg_found = False

            for kw in enforced_keywords:
                if kw in combined_text:
                    pos_found = True
                    break

            for kw in not_enforced_keywords:
                if kw in combined_text:
                    neg_found = True
                    break

            item_id = str(item.get("id", item.get("jobId", "unknown")))
            if neg_found:
                not_enforced_evidence.append(item_id)
            elif pos_found:
                enforced_evidence.append(item_id)

        is_enforced = len(enforced_evidence) > 0 and len(not_enforced_evidence) == 0

        return {
            "isBannerModeEnforced": is_enforced,
            "totalJobResults": total_results,
            "enforcedEvidenceCount": len(enforced_evidence),
            "notEnforcedEvidenceCount": len(not_enforced_evidence),
            "evaluationNote": "Evaluated from BrazenCloud job result outputs for banner enforcement policy indicators"
        }
    except Exception as e:
        return {"isBannerModeEnforced": False, "error": str(e)}


def transform(input):
    criteriaKey = "isBannerModeEnforced"
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))
        data, validation = extract_input(input)
        if validation.get("status") == "failed":
            return create_response(
                result={criteriaKey: False},
                validation=validation,
                fail_reasons=["Input validation failed"]
            )
        eval_result = evaluate(data)
        result_value = eval_result.get(criteriaKey, False)

        extra_fields = {}
        for k in eval_result:
            if k != criteriaKey and k != "error":
                extra_fields[k] = eval_result[k]

        result_dict = {criteriaKey: result_value}
        for k in extra_fields:
            result_dict[k] = extra_fields[k]

        summary_dict = {criteriaKey: result_value}
        for k in extra_fields:
            summary_dict[k] = extra_fields[k]

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        if result_value:
            pass_reasons.append("Banner mode enforcement policies are active in the cloud environment")
            pass_reasons.append("Job results confirm login/legal notice banner configuration is enforced")
            for k in extra_fields:
                pass_reasons.append(k + ": " + str(extra_fields[k]))
        else:
            fail_reasons.append("Banner mode enforcement policies are not confirmed as active")
            if "error" in eval_result:
                fail_reasons.append("Evaluation error: " + eval_result["error"])
            recommendations.append(
                "Enable and configure a legal notice or login warning banner across all systems and cloud tenants"
            )
            recommendations.append(
                "Set interactive logon message text and caption via Group Policy or equivalent cloud policy mechanisms"
            )
            recommendations.append(
                "Ensure BrazenCloud banner enforcement scanning jobs have executed and results are available"
            )

        return create_response(
            result=result_dict,
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary=summary_dict
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
