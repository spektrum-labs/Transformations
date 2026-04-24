"""
Transformation: authTypesAllowed
Vendor: Google  |  Category: iam
Evaluates: Parses login activity event records to identify which authentication types
are active across the organization. Evaluates event parameters such as login_type
and is_second_factor to enumerate allowed auth methods (e.g. password, security key,
authenticator app, SAML). Returns the set of confirmed authentication types in use.
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
            "dataCollection": {"status": "error" if (api_errors or []) else "success", "errors": api_errors or []},
            "validation": {"status": validation.get("status", "unknown"), "errors": validation.get("errors", []), "warnings": validation.get("warnings", [])},
            "transformation": {"status": "error" if (transformation_errors or []) else "success", "errors": transformation_errors or [], "inputSummary": input_summary or {}},
            "evaluation": {"passReasons": pass_reasons or [], "failReasons": fail_reasons or [], "recommendations": recommendations or [], "additionalFindings": additional_findings or []},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "authTypesAllowed", "vendor": "Google", "category": "iam"}
        }
    }


def evaluate(data):
    try:
        items = data.get("items", [])
        if not items:
            return {
                "authTypesAllowed": False,
                "authTypes": [],
                "authTypeCounts": {},
                "secondFactorCounts": {},
                "totalLoginEvents": 0,
                "totalActivityItems": 0,
                "hasStrongAuthType": False,
                "error": "No login activity items found in response"
            }

        seen_types = {}
        auth_type_counts = {}
        second_factor_counts = {}
        total_events = 0

        for item in items:
            events = item.get("events", [])
            for event in events:
                total_events = total_events + 1
                params = event.get("parameters", [])
                login_type = None
                is_second_factor = False

                for param in params:
                    param_name = param.get("name", "")
                    if param_name == "login_type":
                        login_type = param.get("value", "unknown")
                    if param_name == "is_second_factor":
                        is_second_factor = param.get("boolValue", False)

                if login_type:
                    seen_types[login_type] = True
                    if login_type in auth_type_counts:
                        auth_type_counts[login_type] = auth_type_counts[login_type] + 1
                    else:
                        auth_type_counts[login_type] = 1
                    if is_second_factor:
                        if login_type in second_factor_counts:
                            second_factor_counts[login_type] = second_factor_counts[login_type] + 1
                        else:
                            second_factor_counts[login_type] = 1

        auth_types_list = [k for k in seen_types]
        has_auth_types = len(auth_types_list) > 0

        strong_types = ["saml", "security_key", "totp"]
        has_strong = False
        for t in auth_types_list:
            if t in strong_types:
                has_strong = True
                break

        return {
            "authTypesAllowed": has_auth_types,
            "authTypes": auth_types_list,
            "authTypeCounts": auth_type_counts,
            "secondFactorCounts": second_factor_counts,
            "totalLoginEvents": total_events,
            "totalActivityItems": len(items),
            "hasStrongAuthType": has_strong
        }
    except Exception as e:
        return {"authTypesAllowed": False, "error": str(e)}


def transform(input):
    criteriaKey = "authTypesAllowed"
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))
        data, validation = extract_input(input)
        if validation.get("status") == "failed":
            return create_response(result={criteriaKey: False}, validation=validation, fail_reasons=["Input validation failed"])
        eval_result = evaluate(data)
        result_value = eval_result.get(criteriaKey, False)

        extra_fields = {}
        for k in eval_result:
            if k != criteriaKey and k != "error":
                extra_fields[k] = eval_result[k]

        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []

        auth_types = eval_result.get("authTypes", [])

        if result_value:
            pass_reasons.append("Authentication types identified: " + ", ".join(auth_types))
            if eval_result.get("hasStrongAuthType", False):
                pass_reasons.append("Strong authentication type(s) in use (SAML, Security Key, or TOTP)")
            additional_findings.append("Total login events analyzed: " + str(eval_result.get("totalLoginEvents", 0)))
            additional_findings.append("Total activity items processed: " + str(eval_result.get("totalActivityItems", 0)))
        else:
            fail_reasons.append("No authentication types could be identified from login activity data")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Ensure the Reports API is enabled and login activity data is available")
            recommendations.append("Verify that the service account has the admin.reports.audit.readonly OAuth scope")

        result_dict = {criteriaKey: result_value}
        for k in extra_fields:
            result_dict[k] = extra_fields[k]

        return create_response(
            result=result_dict,
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={"totalItems": eval_result.get("totalActivityItems", 0), "authTypeCount": len(auth_types)}
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
