"""
Transformation: authTypesAllowed
Vendor: Google  |  Category: cloud-security-alliance-star-csa-star
Evaluates: Parses login activity events and extracts distinct login_type parameter
values (e.g. google_password, saml, passkey) from items[].events[].parameters
to determine which authentication types are permitted and in use across the domain.
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
                "transformationId": "authTypesAllowed",
                "vendor": "Google",
                "category": "cloud-security-alliance-star-csa-star"
            }
        }
    }


def evaluate(data):
    """
    Iterates login audit log items and collects distinct login_type values
    from events[].parameters[]. Returns the list of auth types in use and
    whether the collection succeeded (non-empty items means logging is active
    and auth types could be identified).
    """
    try:
        items = data.get("items", [])
        if not isinstance(items, list):
            items = []

        auth_types = []
        total_events_scanned = 0
        login_events_found = 0

        for item in items:
            events = item.get("events", [])
            if not isinstance(events, list):
                events = []
            for event in events:
                total_events_scanned = total_events_scanned + 1
                parameters = event.get("parameters", [])
                if not isinstance(parameters, list):
                    parameters = []
                for param in parameters:
                    if param.get("name") == "login_type":
                        val = param.get("value", "")
                        if val:
                            login_events_found = login_events_found + 1
                            if val not in auth_types:
                                auth_types.append(val)

        has_auth_types = len(auth_types) > 0

        return {
            "authTypesAllowed": has_auth_types,
            "authTypesList": auth_types,
            "totalAuthTypes": len(auth_types),
            "totalItemsAnalyzed": len(items),
            "totalEventsScanned": total_events_scanned,
            "loginEventsFound": login_events_found
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

        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []

        auth_types_list = eval_result.get("authTypesList", [])
        total_items = eval_result.get("totalItemsAnalyzed", 0)

        if result_value:
            pass_reasons.append("Authentication types successfully identified from login audit logs")
            pass_reasons.append("Total distinct auth types in use: " + str(len(auth_types_list)))
            for at in auth_types_list:
                additional_findings.append("Auth type in use: " + str(at))
        else:
            fail_reasons.append("No authentication type data could be extracted from login audit logs")
            if total_items == 0:
                fail_reasons.append("Login audit log returned no items — logging may not be active or data is unavailable")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Ensure Google Workspace login audit logs are enabled and the OAuth token has the admin.reports.audit.readonly scope")

        combined_result = {criteriaKey: result_value}
        for k in extra_fields:
            combined_result[k] = extra_fields[k]

        return create_response(
            result=combined_result,
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={
                "totalItemsAnalyzed": total_items,
                "totalAuthTypesFound": len(auth_types_list)
            }
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
