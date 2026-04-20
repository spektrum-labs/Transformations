"""
Transformation: authTypesAllowed
Vendor: Google  |  Category: cloud-security-alliance-star-csa-star
Evaluates: Which authentication types are observed in login activity events for the domain,
           and whether only strong/approved authentication types are in use.
"""
import json
from datetime import datetime


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for _ in range(3):
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "authTypesAllowed", "vendor": "Google", "category": "cloud-security-alliance-star-csa-star"}
        }
    }


def evaluate(data):
    """
    Extracts the login_type event parameter from each item's events array in the
    Google Workspace login activity report. Evaluates whether all observed authentication
    types are within the approved set (google_password, saml, exchange).
    """
    try:
        items = data.get("items", [])
        if not isinstance(items, list):
            items = []

        # Approved strong authentication types
        approved_types = ["google_password", "saml", "exchange"]

        login_type_counts = {}

        for item in items:
            events = item.get("events", [])
            if not isinstance(events, list):
                events = []
            for event in events:
                params = event.get("parameters", [])
                if not isinstance(params, list):
                    params = []
                for param in params:
                    if param.get("name") == "login_type":
                        lt = param.get("value", "unknown")
                        if lt in login_type_counts:
                            login_type_counts[lt] = login_type_counts[lt] + 1
                        else:
                            login_type_counts[lt] = 1

        observed_types = [t for t in login_type_counts]
        unapproved_types = [t for t in observed_types if t not in approved_types]
        approved_observed = [t for t in observed_types if t in approved_types]

        has_login_events = len(observed_types) > 0
        all_approved = len(unapproved_types) == 0

        # Pass only when login events exist and all observed types are approved
        result = has_login_events and all_approved

        return {
            "authTypesAllowed": result,
            "observedLoginTypes": observed_types,
            "approvedLoginTypes": approved_observed,
            "unapprovedLoginTypes": unapproved_types,
            "totalLoginEvents": len(items)
        }
    except Exception as e:
        return {"authTypesAllowed": False, "error": str(e)}


def transform(input):
    criteria_key = "authTypesAllowed"
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        if validation.get("status") == "failed":
            return create_response(
                result={criteria_key: False},
                validation=validation,
                fail_reasons=["Input validation failed"]
            )

        eval_result = evaluate(data)
        result_value = eval_result.get(criteria_key, False)

        extra_fields = {}
        for k in eval_result:
            if k != criteria_key and k != "error":
                extra_fields[k] = eval_result[k]

        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []

        observed = extra_fields.get("observedLoginTypes", [])
        unapproved = extra_fields.get("unapprovedLoginTypes", [])

        if result_value:
            pass_reasons.append("All observed authentication types are approved: " + ", ".join(observed))
            pass_reasons.append("No unapproved or weak authentication types detected in login activity events.")
        else:
            if len(observed) == 0:
                fail_reasons.append("No login activity events were found — unable to confirm which authentication types are permitted.")
                recommendations.append("Ensure the Google Workspace Admin SDK Reports API is returning login activity data and that the integration has sufficient permissions.")
            else:
                fail_reasons.append("Unapproved authentication types observed in login activity: " + ", ".join(unapproved))
                recommendations.append("Review and restrict authentication types in the Google Admin console to only allow approved methods (google_password, saml, exchange).")
            if "error" in eval_result:
                fail_reasons.append("Evaluation error: " + eval_result["error"])

        if len(observed) > 0:
            additional_findings.append("Observed authentication types: " + ", ".join(observed))

        result_dict = {criteria_key: result_value}
        for k in extra_fields:
            result_dict[k] = extra_fields[k]

        summary_dict = {criteria_key: result_value}
        for k in extra_fields:
            summary_dict[k] = extra_fields[k]

        return create_response(
            result=result_dict,
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary=summary_dict,
            additional_findings=additional_findings
        )

    except Exception as e:
        return create_response(
            result={criteria_key: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
