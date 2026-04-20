"""
Transformation: authTypesAllowed
Vendor: Google  |  Category: IAM
Evaluates: Analyses login activity events from the Reports API login application to identify
which authentication types and second-factor methods are recorded as in-use across the
Google Workspace domain.
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "authTypesAllowed", "vendor": "Google", "category": "IAM"}
        }
    }


def evaluate(data):
    try:
        items = data.get("items", [])
        if not isinstance(items, list):
            items = []

        # Filter for login application events specifically; fall back to all items
        login_items = [
            item for item in items
            if isinstance(item, dict)
            and isinstance(item.get("id"), dict)
            and item.get("id", {}).get("applicationName") == "login"
        ]
        if not login_items and items:
            login_items = items

        login_types_seen = {}
        challenge_methods_seen = {}
        total_events = 0

        for item in login_items:
            events = item.get("events", [])
            if not isinstance(events, list):
                events = []
            for event in events:
                if not isinstance(event, dict):
                    continue
                total_events = total_events + 1
                params = event.get("parameters", [])
                if not isinstance(params, list):
                    params = []
                for param in params:
                    if not isinstance(param, dict):
                        continue
                    pname = param.get("name", "")
                    pvalue = param.get("value", "")
                    if pname == "login_type" and pvalue:
                        if pvalue in login_types_seen:
                            login_types_seen[pvalue] = login_types_seen[pvalue] + 1
                        else:
                            login_types_seen[pvalue] = 1
                    if pname == "login_challenge_method" and pvalue:
                        if pvalue in challenge_methods_seen:
                            challenge_methods_seen[pvalue] = challenge_methods_seen[pvalue] + 1
                        else:
                            challenge_methods_seen[pvalue] = 1

        observed_login_types = [t for t in login_types_seen]
        observed_challenge_methods = [m for m in challenge_methods_seen]

        secure_methods = ["totp", "security_key", "backup_code", "idv_preregistered_phone", "phone", "internal_two_factor"]
        has_secure_methods = False
        for m in observed_challenge_methods:
            if m in secure_methods:
                has_secure_methods = True
                break

        all_none = True
        for m in observed_challenge_methods:
            if m != "none":
                all_none = False
                break
        insecure_only = len(observed_challenge_methods) > 0 and all_none

        has_data = len(login_items) > 0 and total_events > 0
        result_value = has_data and has_secure_methods

        return {
            "authTypesAllowed": result_value,
            "observedLoginTypes": observed_login_types,
            "observedChallengeMethods": observed_challenge_methods,
            "loginTypeCounts": {lt: login_types_seen[lt] for lt in login_types_seen},
            "challengeMethodCounts": {cm: challenge_methods_seen[cm] for cm in challenge_methods_seen},
            "totalLoginEventsAnalysed": total_events,
            "totalLoginItemsAnalysed": len(login_items),
            "hasSecureAuthMethods": has_secure_methods,
            "insecureOnlyAuthDetected": insecure_only
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
        extra_fields = {k: eval_result[k] for k in eval_result if k != criteriaKey and k != "error"}
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []
        if result_value:
            pass_reasons.append("Login activity is present and secure authentication methods are observed across the domain")
            challenge_methods = eval_result.get("observedChallengeMethods", [])
            if challenge_methods:
                pass_reasons.append("Secure challenge methods observed: " + ", ".join(challenge_methods))
            login_types = eval_result.get("observedLoginTypes", [])
            if login_types:
                pass_reasons.append("Login types recorded: " + ", ".join(login_types))
        else:
            total_events = eval_result.get("totalLoginEventsAnalysed", 0)
            if total_events == 0:
                fail_reasons.append("No login activity events found; cannot determine allowed authentication types")
                recommendations.append("Ensure the Google Reports API login scope is authorised and login activity logs are being collected")
            elif eval_result.get("insecureOnlyAuthDetected"):
                fail_reasons.append("Only password-only login events detected; no MFA challenge methods observed in login activity")
                recommendations.append("Enable and enforce Multi-Factor Authentication (2-Step Verification) for all users in the Google Workspace Admin Console under Security > 2-Step Verification")
            elif not eval_result.get("hasSecureAuthMethods"):
                fail_reasons.append("No secure second-factor authentication methods detected in login activity")
                recommendations.append("Configure MFA policies and enforce 2-Step Verification for all Google Workspace users")
            if "error" in eval_result:
                fail_reasons.append("Evaluation error: " + eval_result["error"])
        challenge_methods = eval_result.get("observedChallengeMethods", [])
        if challenge_methods:
            additional_findings.append("Second-factor methods observed: " + ", ".join(challenge_methods))
        login_types = eval_result.get("observedLoginTypes", [])
        if login_types:
            additional_findings.append("Authentication types in use: " + ", ".join(login_types))
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
            input_summary={
                "totalLoginEventsAnalysed": eval_result.get("totalLoginEventsAnalysed", 0),
                "totalLoginItemsAnalysed": eval_result.get("totalLoginItemsAnalysed", 0),
                "observedLoginTypes": eval_result.get("observedLoginTypes", []),
                "observedChallengeMethods": eval_result.get("observedChallengeMethods", [])
            }
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False}, validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)], fail_reasons=["Transformation error: " + str(e)])
